// internal/security/bogon.go
package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"qff/internal/config"
	"qff/internal/logger"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	// Default configuration
	DefaultUpdateInterval  = 24 * time.Hour // Daily updates
	DefaultDownloadTimeout = 5 * time.Minute
	DefaultMaxFileSize     = 10 * 1024 * 1024 // 10MB max
	DefaultRetryAttempts   = 3
	DefaultRetryDelay      = 30 * time.Second

	// Set names
	BOGONChain        = "bogon_chain"
	BOGONIPv4Set      = "bogon_ipv4_nets"
	BOGONIPv6Set      = "bogon_ipv6_nets"
	BOGONWhitelistSet = "bogon_whitelist"

	// Cache settings
	DefaultCacheDir = "/var/lib/qff/bogon"
	CacheFileFormat = "bogon_%s_%s.cache"

	// Well-known BOGON list URLs
	TeamCymruIPv4URL = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
	TeamCymruIPv6URL = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"
	SpamhausIPv4URL  = "https://www.spamhaus.org/drop/drop.txt"
	SpamhausIPv6URL  = "https://www.spamhaus.org/drop/dropv6.txt"
)

// BOGONManager handles BOGON (Bogus IP) filtering using nftables
type BOGONManager struct {
	// Core components
	config *Config
	conn   *nftables.Conn
	table  *nftables.Table

	// State management
	mu        sync.RWMutex
	bogonNets map[string][]net.IPNet // Keyed by source (ipv4/ipv6)
	stats     *BOGONStats

	// HTTP client for downloads
	client *http.Client

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds BOGON filtering configuration
type Config struct {
	// Enable/disable BOGON filtering
	EnableBogonFilter bool `json:"enable_bogon_filter"`
	EnableIPv6        bool `json:"enable_ipv6"`

	// Update settings
	UpdateInterval  time.Duration `json:"update_interval"`
	DownloadTimeout time.Duration `json:"download_timeout"`
	MaxFileSize     int64         `json:"max_file_size"`
	RetryAttempts   int           `json:"retry_attempts"`
	RetryDelay      time.Duration `json:"retry_delay"`

	// Sources
	IPv4Sources []BOGONSource `json:"ipv4_sources"`
	IPv6Sources []BOGONSource `json:"ipv6_sources"`

	// Cache settings
	EnableCache    bool          `json:"enable_cache"`
	CacheDirectory string        `json:"cache_directory"`
	CacheExpiry    time.Duration `json:"cache_expiry"`

	// Whitelist settings
	WhitelistedNetworks []string `json:"whitelisted_networks"`

	// Action settings
	DefaultAction   string `json:"default_action"` // drop, reject, log
	LogBogonPackets bool   `json:"log_bogon_packets"`
	CounterEnabled  bool   `json:"counter_enabled"`
}

// BOGONSource represents a source for BOGON network lists
type BOGONSource struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	Format      string `json:"format"` // cidr, spamhaus, cymru
	Description string `json:"description"`
}

// BOGONStats provides statistics about BOGON filtering
type BOGONStats struct {
	// Network counts
	IPv4Networks        int `json:"ipv4_networks"`
	IPv6Networks        int `json:"ipv6_networks"`
	WhitelistedNetworks int `json:"whitelisted_networks"`

	// Update statistics
	LastUpdate         time.Time     `json:"last_update"`
	LastUpdateDuration time.Duration `json:"last_update_duration"`
	UpdateCount        int64         `json:"update_count"`
	FailedUpdates      int64         `json:"failed_updates"`

	// Traffic statistics (if counters enabled)
	BlockedPackets int64 `json:"blocked_packets"`
	BlockedBytes   int64 `json:"blocked_bytes"`

	// Source statistics
	SourceStats map[string]*SourceStats `json:"source_stats"`
}

// SourceStats tracks statistics for individual BOGON sources
type SourceStats struct {
	Name         string        `json:"name"`
	LastFetch    time.Time     `json:"last_fetch"`
	LastSuccess  time.Time     `json:"last_success"`
	FetchCount   int64         `json:"fetch_count"`
	FailureCount int64         `json:"failure_count"`
	NetworkCount int           `json:"network_count"`
	LastError    string        `json:"last_error,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
	ContentHash  string        `json:"content_hash"`
}

func NewBOGONManager(cfg *config.SecurityConfig, conn *nftables.Conn, table *nftables.Table) *BOGONManager {
	ctx, cancel := context.WithCancel(context.Background())

	// Convert old config to new config format
	newConfig := convertConfig(cfg)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: newConfig.DownloadTimeout,
		Transport: &http.Transport{
			MaxIdleConns:       5,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
			MaxConnsPerHost:    2,
		},
	}

	return &BOGONManager{
		config:    newConfig,
		conn:      conn,
		table:     table,
		bogonNets: make(map[string][]net.IPNet),
		stats:     &BOGONStats{SourceStats: make(map[string]*SourceStats)},
		client:    client,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func convertConfig(oldCfg *config.SecurityConfig) *Config {
	if oldCfg == nil {
		return getDefaultConfig()
	}

	config := &Config{
		EnableBogonFilter:   oldCfg.EnableBogonFilter,
		EnableIPv6:          true,
		UpdateInterval:      getUpdateInterval(oldCfg.BogonUpdateInterval),
		DownloadTimeout:     DefaultDownloadTimeout,
		MaxFileSize:         DefaultMaxFileSize,
		RetryAttempts:       DefaultRetryAttempts,
		RetryDelay:          DefaultRetryDelay,
		EnableCache:         true,
		CacheDirectory:      DefaultCacheDir,
		CacheExpiry:         24 * time.Hour,
		DefaultAction:       "drop",
		LogBogonPackets:     false,
		CounterEnabled:      true,
		WhitelistedNetworks: []string{},
	}

	// Add default sources
	config.IPv4Sources = getDefaultIPv4Sources()
	config.IPv6Sources = getDefaultIPv6Sources()

	// Add custom URL if provided
	if oldCfg.BogonIPv4URL != "" {
		config.IPv4Sources = append(config.IPv4Sources, BOGONSource{
			Name:        "custom_ipv4",
			URL:         oldCfg.BogonIPv4URL,
			Enabled:     true,
			Format:      "cidr",
			Description: "Custom IPv4 BOGON source",
		})
	}

	return config
}

func getDefaultConfig() *Config {
	return &Config{
		EnableBogonFilter:   false,
		EnableIPv6:          true,
		UpdateInterval:      DefaultUpdateInterval,
		DownloadTimeout:     DefaultDownloadTimeout,
		MaxFileSize:         DefaultMaxFileSize,
		RetryAttempts:       DefaultRetryAttempts,
		RetryDelay:          DefaultRetryDelay,
		EnableCache:         true,
		CacheDirectory:      DefaultCacheDir,
		CacheExpiry:         24 * time.Hour,
		DefaultAction:       "drop",
		LogBogonPackets:     false,
		CounterEnabled:      true,
		IPv4Sources:         getDefaultIPv4Sources(),
		IPv6Sources:         getDefaultIPv6Sources(),
		WhitelistedNetworks: []string{},
	}
}

func getUpdateInterval(oldInterval time.Duration) time.Duration {
	if oldInterval > 0 {
		return oldInterval
	}
	return DefaultUpdateInterval
}

func getDefaultIPv4Sources() []BOGONSource {
	return []BOGONSource{
		{
			Name:        "team_cymru_ipv4",
			URL:         TeamCymruIPv4URL,
			Enabled:     true,
			Format:      "cidr",
			Description: "Team Cymru IPv4 BOGON list",
		},
		{
			Name:        "spamhaus_drop",
			URL:         SpamhausIPv4URL,
			Enabled:     true,
			Format:      "spamhaus",
			Description: "Spamhaus DROP list",
		},
	}
}

func getDefaultIPv6Sources() []BOGONSource {
	return []BOGONSource{
		{
			Name:        "team_cymru_ipv6",
			URL:         TeamCymruIPv6URL,
			Enabled:     true,
			Format:      "cidr",
			Description: "Team Cymru IPv6 BOGON list",
		},
		{
			Name:        "spamhaus_dropv6",
			URL:         SpamhausIPv6URL,
			Enabled:     true,
			Format:      "spamhaus",
			Description: "Spamhaus DROPv6 list",
		},
	}
}

func (b *BOGONManager) Initialize() error {
	if !b.config.EnableBogonFilter {
		logger.Info("bogon", "BOGON filtering is disabled")
		return nil
	}

	logger.Info("bogon", "Initializing BOGON filtering",
		"ipv4_sources", len(b.config.IPv4Sources),
		"ipv6_sources", len(b.config.IPv6Sources),
		"cache_enabled", b.config.EnableCache)

	// Create cache directory
	if b.config.EnableCache {
		if err := os.MkdirAll(b.config.CacheDirectory, 0755); err != nil {
			logger.Warn("bogon", "Failed to create cache directory", "error", err.Error())
		}
	}

	// Create nftables sets
	if err := b.createNFTablesSets(); err != nil {
		return fmt.Errorf("failed to create nftables sets: %w", err)
	}

	// Load default BOGON networks first
	if err := b.loadDefaultBogonNetworks(); err != nil {
		logger.Warn("bogon", "Failed to load default BOGON networks", "error", err.Error())
	}

	// Initialize whitelisted networks
	if err := b.initializeWhitelistedNetworks(); err != nil {
		logger.Warn("bogon", "Failed to initialize whitelisted networks", "error", err.Error())
	}

	// Load from cache if available
	if b.config.EnableCache {
		b.loadFromCache()
	}

	// Start periodic updates
	if b.config.UpdateInterval > 0 {
		b.startBogonUpdater()
	}

	// Initial update if no cached data
	if b.shouldPerformInitialUpdate() {
		go b.updateAllSources()
	}

	return nil
}

func (b *BOGONManager) createNFTablesSets() error {
	// Define set configurations
	sets := []struct {
		name     string
		keyType  nftables.SetDatatype
		interval bool
		isIPv6   bool
	}{
		{
			name:     BOGONIPv4Set,
			keyType:  nftables.TypeIPAddr,
			interval: true,
			isIPv6:   false,
		},
		{
			name:     BOGONWhitelistSet,
			keyType:  nftables.TypeIPAddr,
			interval: true,
			isIPv6:   false,
		},
	}

	// Add IPv6 set if enabled
	if b.config.EnableIPv6 {
		sets = append(sets, struct {
			name     string
			keyType  nftables.SetDatatype
			interval bool
			isIPv6   bool
		}{
			name:     BOGONIPv6Set,
			keyType:  nftables.TypeIP6Addr,
			interval: true,
			isIPv6:   true,
		})
	}

	// Create each set
	for _, setCfg := range sets {
		set := &nftables.Set{
			Name:     setCfg.name,
			Table:    b.table,
			KeyType:  setCfg.keyType,
			Interval: setCfg.interval,
		}

		if err := b.conn.AddSet(set, nil); err != nil {
			return fmt.Errorf("failed to create set %s: %w", setCfg.name, err)
		}
	}

	return nil
}

func (b *BOGONManager) loadDefaultBogonNetworks() error {
	// RFC-defined BOGON networks
	defaultBogonsIPv4 := []string{
		"0.0.0.0/8",          // "This network"
		"10.0.0.0/8",         // Private-Use
		"100.64.0.0/10",      // Shared Address Space
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link Local
		"172.16.0.0/12",      // Private-Use
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // Documentation (TEST-NET-1)
		"192.168.0.0/16",     // Private-Use
		"198.18.0.0/15",      // Benchmarking
		"198.51.100.0/24",    // Documentation (TEST-NET-2)
		"203.0.113.0/24",     // Documentation (TEST-NET-3)
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for Future Use
		"255.255.255.255/32", // Broadcast
	}

	// Parse and store IPv4 networks
	var ipv4Networks []net.IPNet
	for _, cidr := range defaultBogonsIPv4 {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Warn("bogon", "Failed to parse default BOGON network", "cidr", cidr, "error", err.Error())
			continue
		}
		ipv4Networks = append(ipv4Networks, *network)
	}

	// Update nftables set
	if err := b.updateNFTablesSet(BOGONIPv4Set, ipv4Networks); err != nil {
		return fmt.Errorf("failed to update IPv4 BOGON set: %w", err)
	}

	b.mu.Lock()
	b.bogonNets["default_ipv4"] = ipv4Networks
	b.stats.IPv4Networks = len(ipv4Networks)
	b.mu.Unlock()

	logger.Info("bogon", "Loaded default IPv4 BOGON networks", "count", len(ipv4Networks))

	// Load IPv6 BOGONs if enabled
	if b.config.EnableIPv6 {
		defaultBogonsIPv6 := []string{
			"::/128",        // Unspecified
			"::1/128",       // Loopback
			"::ffff:0:0/96", // IPv4-mapped
			"64:ff9b::/96",  // IPv4-IPv6 Translation
			"100::/64",      // Discard-Only
			"2001::/23",     // IETF Protocol Assignments
			"2001:db8::/32", // Documentation
			"fc00::/7",      // Unique Local
			"fe80::/10",     // Link Local
			"ff00::/8",      // Multicast
		}

		var ipv6Networks []net.IPNet
		for _, cidr := range defaultBogonsIPv6 {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				logger.Warn("bogon", "Failed to parse default IPv6 BOGON network", "cidr", cidr, "error", err.Error())
				continue
			}
			ipv6Networks = append(ipv6Networks, *network)
		}

		if err := b.updateNFTablesSet(BOGONIPv6Set, ipv6Networks); err != nil {
			return fmt.Errorf("failed to update IPv6 BOGON set: %w", err)
		}

		b.mu.Lock()
		b.bogonNets["default_ipv6"] = ipv6Networks
		b.stats.IPv6Networks = len(ipv6Networks)
		b.mu.Unlock()

		logger.Info("bogon", "Loaded default IPv6 BOGON networks", "count", len(ipv6Networks))
	}

	return nil
}

func (b *BOGONManager) initializeWhitelistedNetworks() error {
	if len(b.config.WhitelistedNetworks) == 0 {
		return nil
	}

	var networks []net.IPNet
	for _, networkStr := range b.config.WhitelistedNetworks {
		_, network, err := net.ParseCIDR(networkStr)
		if err != nil {
			ip := net.ParseIP(networkStr)
			if ip == nil {
				logger.Warn("bogon", "Invalid whitelisted network", "network", networkStr)
				continue
			}
			// Convert single IP to /32 or /128 network
			if ip.To4() != nil {
				_, network, _ = net.ParseCIDR(networkStr + "/32")
			} else {
				_, network, _ = net.ParseCIDR(networkStr + "/128")
			}
		}
		networks = append(networks, *network)
	}

	if len(networks) > 0 {
		if err := b.updateNFTablesSet(BOGONWhitelistSet, networks); err != nil {
			return fmt.Errorf("failed to update whitelist set: %w", err)
		}

		b.mu.Lock()
		b.stats.WhitelistedNetworks = len(networks)
		b.mu.Unlock()

		logger.Info("bogon", "Initialized whitelisted networks", "count", len(networks))
	}

	return nil
}

func (b *BOGONManager) shouldPerformInitialUpdate() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Perform initial update if we have no external BOGON data
	for sourceName := range b.stats.SourceStats {
		if sourceName != "default_ipv4" && sourceName != "default_ipv6" {
			return false // We have external data
		}
	}

	return true
}

func (b *BOGONManager) startBogonUpdater() {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		ticker := time.NewTicker(b.config.UpdateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				b.updateAllSources()
			case <-b.ctx.Done():
				return
			}
		}
	}()
}

func (b *BOGONManager) updateAllSources() {
	startTime := time.Now()
	logger.Info("bogon", "Starting BOGON list update")

	var wg sync.WaitGroup

	// Update IPv4 sources
	for _, source := range b.config.IPv4Sources {
		if !source.Enabled {
			continue
		}

		wg.Add(1)
		go func(src BOGONSource) {
			defer wg.Done()
			b.updateSource(src, "ipv4")
		}(source)
	}

	// Update IPv6 sources if enabled
	if b.config.EnableIPv6 {
		for _, source := range b.config.IPv6Sources {
			if !source.Enabled {
				continue
			}

			wg.Add(1)
			go func(src BOGONSource) {
				defer wg.Done()
				b.updateSource(src, "ipv6")
			}(source)
		}
	}

	wg.Wait()

	duration := time.Since(startTime)

	b.mu.Lock()
	b.stats.LastUpdate = time.Now()
	b.stats.LastUpdateDuration = duration
	b.stats.UpdateCount++
	b.mu.Unlock()

	logger.Info("bogon", "BOGON list update completed", "duration", duration)
}

// calculateNetworksHash generates a consistent hash of the network list
func (b *BOGONManager) calculateNetworksHash(networks []net.IPNet) string {
	// Create a hash writer
	h := sha256.New()

	// Write each network to the hash in a consistent format
	for _, network := range networks {
		// Write both IP and mask to catch any changes
		h.Write(network.IP)
		h.Write(network.Mask)
	}

	// Return the hex-encoded hash
	return hex.EncodeToString(h.Sum(nil))
}

func (b *BOGONManager) updateSource(source BOGONSource, ipVersion string) {
	startTime := time.Now()

	b.mu.Lock()
	stats := b.stats.SourceStats[source.Name]
	if stats == nil {
		stats = &SourceStats{Name: source.Name}
		b.stats.SourceStats[source.Name] = stats
	}
	stats.FetchCount++
	stats.LastFetch = startTime
	b.mu.Unlock()

	networks, err := b.downloadAndParseBogonList(source)
	responseTime := time.Since(startTime)

	if err != nil {
		b.mu.Lock()
		stats.FailureCount++
		stats.LastError = err.Error()
		stats.ResponseTime = responseTime
		b.mu.Unlock()

		logger.Error("bogon", "Failed to update BOGON source",
			"source", source.Name, "error", err.Error())
		return
	}

	// Calculate content hash
	hash := b.calculateNetworksHash(networks)

	// Check if content changed
	b.mu.RLock()
	existingHash := stats.ContentHash
	b.mu.RUnlock()

	if hash == existingHash && existingHash != "" {
		logger.Info("bogon", "BOGON source unchanged", "source", source.Name)
		return
	}

	// Update nftables set
	setName := BOGONIPv4Set
	if ipVersion == "ipv6" {
		setName = BOGONIPv6Set
	}

	if err := b.updateNFTablesSet(setName, networks); err != nil {
		b.mu.Lock()
		stats.FailureCount++
		stats.LastError = fmt.Sprintf("nftables update failed: %v", err)
		b.mu.Unlock()

		logger.Error("bogon", "Failed to update nftables set",
			"source", source.Name, "error", err.Error())
		return
	}

	// Update statistics
	b.mu.Lock()
	stats.LastSuccess = time.Now()
	stats.NetworkCount = len(networks)
	stats.LastError = ""
	stats.ResponseTime = responseTime
	stats.ContentHash = hash

	// Store in memory
	b.bogonNets[source.Name] = networks

	// Update global counts
	if ipVersion == "ipv4" {
		totalIPv4 := 0
		for key, nets := range b.bogonNets {
			if strings.Contains(key, "ipv4") || key == "default_ipv4" || (!strings.Contains(key, "ipv6") && !strings.Contains(key, "default")) {
				totalIPv4 += len(nets)
			}
		}
		b.stats.IPv4Networks = totalIPv4
	} else {
		totalIPv6 := 0
		for key, nets := range b.bogonNets {
			if strings.Contains(key, "ipv6") || key == "default_ipv6" {
				totalIPv6 += len(nets)
			}
		}
		b.stats.IPv6Networks = totalIPv6
	}
	b.mu.Unlock()

	// Cache if enabled
	if b.config.EnableCache {
		b.saveToCache(source.Name, networks, hash)
	}

	logger.Info("bogon", "Updated BOGON source",
		"source", source.Name,
		"networks", len(networks),
		"response_time", responseTime)
}

// loadFromCacheSource loads networks for a specific source from cache
func (b *BOGONManager) loadFromCacheSource(sourceName string) ([]net.IPNet, error) {
	cacheFile := b.getCacheFilePath(sourceName)
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var networks []net.IPNet
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue // skip invalid entries
		}
		networks = append(networks, *network)
	}

	return networks, nil
}

// getCacheFilePath returns the full path to a cache file for a source
func (b *BOGONManager) getCacheFilePath(sourceName string) string {
	hash := sha256.Sum256([]byte(sourceName))
	hashStr := hex.EncodeToString(hash[:])
	return filepath.Join(b.config.CacheDirectory, fmt.Sprintf(CacheFileFormat, sourceName, hashStr[:8]))
}

// saveToCache saves networks for a source to cache
func (b *BOGONManager) saveToCache(sourceName string, networks []net.IPNet, hash string) {
	cacheFile := b.getCacheFilePath(sourceName)

	var builder strings.Builder
	for _, network := range networks {
		builder.WriteString(network.String())
		builder.WriteString("\n")
	}

	if err := os.WriteFile(cacheFile, []byte(builder.String()), 0644); err != nil {
		logger.Warn("bogon", "Failed to save cache", "source", sourceName, "error", err.Error())
	}
}

// loadFromCache loads all cached data (called during initialization)
func (b *BOGONManager) loadFromCache() {
	if !b.config.EnableCache {
		return
	}

	// Load cached IPv4 sources
	for _, source := range b.config.IPv4Sources {
		if !source.Enabled {
			continue
		}
		if networks, err := b.loadFromCacheSource(source.Name); err == nil {
			b.bogonNets[source.Name] = networks
			if stats := b.stats.SourceStats[source.Name]; stats != nil {
				stats.NetworkCount = len(networks)
			}
		}
	}

	// Load cached IPv6 sources if enabled
	if b.config.EnableIPv6 {
		for _, source := range b.config.IPv6Sources {
			if !source.Enabled {
				continue
			}
			if networks, err := b.loadFromCacheSource(source.Name); err == nil {
				b.bogonNets[source.Name] = networks
				if stats := b.stats.SourceStats[source.Name]; stats != nil {
					stats.NetworkCount = len(networks)
				}
			}
		}
	}
}

func (b *BOGONManager) downloadAndParseBogonList(source BOGONSource) ([]net.IPNet, error) {
	// Check cache first
	if b.config.EnableCache {
		if networks, err := b.loadFromCacheSource(source.Name); err == nil {
			return networks, nil
		}
	}

	// Download with retries
	var lastErr error
	for attempt := 1; attempt <= b.config.RetryAttempts; attempt++ {
		networks, err := b.downloadBogonList(source)
		if err == nil {
			return networks, nil
		}

		lastErr = err
		if attempt < b.config.RetryAttempts {
			logger.Warn("bogon", "Download attempt failed, retrying",
				"source", source.Name, "attempt", attempt, "error", err.Error())

			select {
			case <-time.After(b.config.RetryDelay):
			case <-b.ctx.Done():
				return nil, b.ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", b.config.RetryAttempts, lastErr)
}

func (b *BOGONManager) downloadBogonList(source BOGONSource) ([]net.IPNet, error) {
	ctx, cancel := context.WithTimeout(b.ctx, b.config.DownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "QFF-BOGON-Manager/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Limit response size
	limitedReader := io.LimitReader(resp.Body, b.config.MaxFileSize)

	return b.parseBogonList(limitedReader, source.Format)
}

func (b *BOGONManager) parseBogonList(reader io.Reader, format string) ([]net.IPNet, error) {
	scanner := bufio.NewScanner(reader)
	var networks []net.IPNet

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse based on format
		var cidr string
		switch format {
		case "spamhaus":
			// Spamhaus format: "1.2.3.0/24 ; SBL12345"
			parts := strings.Split(line, " ")
			if len(parts) > 0 {
				cidr = parts[0]
			}
		case "cymru", "cidr":
			// Simple CIDR format
			cidr = line
		default:
			cidr = line
		}

		if cidr == "" {
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			// Convert to CIDR
			if ip.To4() != nil {
				_, network, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, network, _ = net.ParseCIDR(cidr + "/128")
			}
		}

		if network != nil {
			networks = append(networks, *network)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan input: %w", err)
	}

	// Sort networks for consistent ordering
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].String() < networks[j].String()
	})

	return networks, nil
}

// getNetworkEnd calculates the last IP address in a network
func (b *BOGONManager) getNetworkEnd(network *net.IPNet) net.IP {
	// For IPv4 networks
	if ipv4 := network.IP.To4(); ipv4 != nil {
		end := make(net.IP, len(ipv4))
		copy(end, ipv4)
		for i := range end {
			end[i] |= ^network.Mask[i]
		}
		return end
	}

	// For IPv6 networks
	end := make(net.IP, len(network.IP))
	copy(end, network.IP)
	for i := range end {
		end[i] |= ^network.Mask[i]
	}
	return end
}

func (b *BOGONManager) updateNFTablesSet(setName string, networks []net.IPNet) error {
	set := &nftables.Set{Name: setName, Table: b.table}

	// Clear existing elements
	b.conn.FlushSet(set)

	if len(networks) == 0 {
		return nil
	}

	// Convert networks to set elements
	elements := make([]nftables.SetElement, 0, len(networks))
	for _, network := range networks {
		// For interval sets, we need to specify both start and end
		elements = append(elements, nftables.SetElement{
			Key:         network.IP,
			KeyEnd:      b.getNetworkEnd(&network),
			IntervalEnd: false,
		})
	}

	// Add elements in batches to avoid overwhelming nftables
	batchSize := 1000
	for i := 0; i < len(elements); i += batchSize {
		end := i + batchSize
		if end > len(elements) {
			end = len(elements)
		}

		batch := elements[i:end]
		b.conn.SetAddElements(set, batch)
	}

	// Flush changes
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables changes: %w", err)
	}

	return nil
}

// AddBOGONRules adds the necessary nftables rules for BOGON filtering
func (b *BOGONManager) AddBOGONRules(inputChain *nftables.Chain) error {
	if !b.config.EnableBogonFilter {
		return nil
	}

	// 1. Create a dedicated chain for BOGON filtering
	bogonChain := &nftables.Chain{
		Name:  BOGONChain,
		Table: b.table,
	}
	b.conn.AddChain(bogonChain)

	// 2. Add a rule to the input chain to jump to the BOGON chain
	b.conn.AddRule(&nftables.Rule{
		Table: b.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Verdict{Kind: expr.VerdictJump, Chain: BOGONChain},
		},
	})

	// 3. Add rules to the BOGON chain
	// Rule: Whitelisted networks are not blocked
	b.conn.AddRule(&nftables.Rule{
		Table: b.table,
		Chain: bogonChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: BOGONWhitelistSet},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule: Block IPv4 BOGONs
	ipv4DropRule := &nftables.Rule{
		Table: b.table,
		Chain: bogonChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.AF_INET}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: BOGONIPv4Set},
		},
	}
	if b.config.LogBogonPackets {
		ipv4DropRule.Exprs = append(ipv4DropRule.Exprs, &expr.Log{Data: []byte("QFF-DROP-BOGON-IPv4: ")})
	}
	ipv4DropRule.Exprs = append(ipv4DropRule.Exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	b.conn.AddRule(ipv4DropRule)

	// Rule: Block IPv6 BOGONs if enabled
	if b.config.EnableIPv6 {
		ipv6DropRule := &nftables.Rule{
			Table: b.table,
			Chain: bogonChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.AF_INET6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // saddr_ipv6
				&expr.Lookup{SourceRegister: 1, SetName: BOGONIPv6Set},
			},
		}
		if b.config.LogBogonPackets {
			ipv6DropRule.Exprs = append(ipv6DropRule.Exprs, &expr.Log{Data: []byte("QFF-DROP-BOGON-IPv6: ")})
		}
		ipv6DropRule.Exprs = append(ipv6DropRule.Exprs, &expr.Verdict{Kind: expr.VerdictDrop})
		b.conn.AddRule(ipv6DropRule)
	}

	logger.Info("bogon", "Added BOGON filtering rules to nftables")
	return nil
}
