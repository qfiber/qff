// internal/ips/blocklist.go
package ips

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"bufio"

	"qff/internal/config"
	"qff/internal/logger"
)

const (
	defaultUpdateInterval = 24 * time.Hour
	defaultHTTPTimeout    = 30 * time.Second
	defaultBatchSize      = 1000
	defaultBatchDelay     = 100 * time.Millisecond
)

type ExternalBlocklistManager struct {
	config     *config.IPSConfig
	ipsManager *IPSManager
	blocklists map[string]*Blocklist
	client     *http.Client
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

type Blocklist struct {
	Name       string
	URL        string
	LastUpdate time.Time
	IPCount    int
	Enabled    bool
	ErrorCount int // Track consecutive failures
}

func NewExternalBlocklistManager(cfg *config.IPSConfig, ipsManager *IPSManager) *ExternalBlocklistManager {
	bm := &ExternalBlocklistManager{
		config:     cfg,
		ipsManager: ipsManager,
		blocklists: make(map[string]*Blocklist),
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				MaxConnsPerHost:     5,
				MaxIdleConnsPerHost: 5,
			},
		},
		stopCh: make(chan struct{}),
	}

	bm.initializeBlocklists()
	return bm
}

func (b *ExternalBlocklistManager) initializeBlocklists() {
	if b.config.BlocklistUpdateInterval == 0 {
		b.config.BlocklistUpdateInterval = defaultUpdateInterval
	}

	// Initialize predefined blocklists
	predefinedLists := []struct {
		key     string
		name    string
		url     string
		enabled bool
	}{
		{"spamhaus_drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", b.config.SpamhausEnabled},
		{"spamhaus_edrop", "Spamhaus EDROP", "https://www.spamhaus.org/drop/edrop.txt", b.config.SpamhausEnabled},
		{"dshield_top", "DShield Top Attackers", "https://www.dshield.org/feeds/suspiciousdomains_High.txt", b.config.DShieldEnabled},
		{"abuse_ch", "Abuse.ch IP Blacklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", true},
		{"greensnow", "GreenSnow Blacklist", "https://blocklist.greensnow.co/greensnow.txt", true},
	}

	for _, list := range predefinedLists {
		if list.enabled {
			b.blocklists[list.key] = &Blocklist{
				Name:    list.name,
				URL:     list.url,
				Enabled: true,
			}
		}
	}
}

func (b *ExternalBlocklistManager) Start() error {
	if !b.config.EnableExternalBlocklists {
		logger.Debug("blocklist", "External blocklists disabled in config")
		return nil
	}

	logger.Info("blocklist", "Starting external blocklist manager")

	// Initial update
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.updateAllBlocklists()
	}()

	// Start periodic updates
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.startPeriodicUpdates()
	}()

	return nil
}

func (b *ExternalBlocklistManager) startPeriodicUpdates() {
	ticker := time.NewTicker(b.config.BlocklistUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.updateAllBlocklists()
		case <-b.stopCh:
			return
		}
	}
}

func (b *ExternalBlocklistManager) updateAllBlocklists() {
	logger.Info("blocklist", "Starting blocklist update")

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3) // Limit concurrent downloads

	for name, blocklist := range b.blocklists {
		if !blocklist.Enabled {
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(name string, blocklist *Blocklist) {
			defer wg.Done()
			defer func() { <-semaphore }()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			b.updateBlocklist(ctx, name, blocklist)
		}(name, blocklist)
	}

	wg.Wait()
	logger.Info("blocklist", "Blocklist update completed")
}

func (b *ExternalBlocklistManager) updateBlocklist(ctx context.Context, name string, blocklist *Blocklist) {
	startTime := time.Now()
	logger.Info("blocklist", "Updating blocklist", "name", name, "url", blocklist.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", blocklist.URL, nil)
	if err != nil {
		logger.Error("blocklist", "Failed to create request", "name", name, "error", err)
		return
	}

	req.Header.Set("User-Agent", "QFF-IPS/1.0")
	req.Header.Set("Accept", "text/plain")

	resp, err := b.client.Do(req)
	if err != nil {
		b.handleBlocklistError(name, blocklist, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b.handleBlocklistError(name, blocklist, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
		return
	}

	ips, err := b.parseBlocklist(resp.Body, name)
	if err != nil {
		b.handleBlocklistError(name, blocklist, err)
		return
	}

	if len(ips) == 0 {
		logger.Warn("blocklist", "Empty blocklist received", "name", name)
		return
	}

	// Update firewall rules
	b.applyBlocklist(name, ips)

	// Update metadata
	b.mu.Lock()
	blocklist.LastUpdate = time.Now()
	blocklist.IPCount = len(ips)
	blocklist.ErrorCount = 0 // Reset error count on success
	b.mu.Unlock()

	logger.Info("blocklist", "Blocklist updated",
		"name", name,
		"ips", len(ips),
		"duration", time.Since(startTime).String())
}

func (b *ExternalBlocklistManager) handleBlocklistError(name string, blocklist *Blocklist, err error) {
	b.mu.Lock()
	blocklist.ErrorCount++
	if blocklist.ErrorCount > 3 {
		blocklist.Enabled = false
		logger.Warn("blocklist", "Disabling blocklist after consecutive failures",
			"name", name,
			"errors", blocklist.ErrorCount)
	}
	b.mu.Unlock()

	logger.Error("blocklist", "Failed to update blocklist",
		"name", name,
		"error", err.Error(),
		"consecutive_errors", blocklist.ErrorCount)
}

func (b *ExternalBlocklistManager) parseBlocklist(body io.Reader, listName string) ([]net.IP, error) {
	var ips []net.IP
	scanner := bufio.NewScanner(body)
	uniqueIPs := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Extract IP/CIDR from line
		ipStr := line
		if parts := strings.SplitN(line, ";", 2); len(parts) > 0 {
			ipStr = strings.TrimSpace(parts[0])
		}

		// Parse IP or CIDR
		var ip net.IP
		if strings.Contains(ipStr, "/") {
			_, cidr, err := net.ParseCIDR(ipStr)
			if err != nil {
				continue
			}
			ip = cidr.IP
		} else {
			ip = net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
		}

		// Deduplicate
		ipStr = ip.String()
		if _, exists := uniqueIPs[ipStr]; !exists {
			uniqueIPs[ipStr] = struct{}{}
			ips = append(ips, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return ips, nil
}

func (b *ExternalBlocklistManager) applyBlocklist(name string, ips []net.IP) {
	setName := fmt.Sprintf("blocklist_%s", strings.ReplaceAll(name, " ", "_"))

	// Remove old entries
	if err := b.ipsManager.firewall.RemoveBlocklistSet(setName); err != nil {
		logger.Error("blocklist", "Failed to remove old blocklist",
			"name", name,
			"error", err.Error())
		return
	}

	// Add new entries in batches
	for i := 0; i < len(ips); i += defaultBatchSize {
		end := i + defaultBatchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]
		if err := b.ipsManager.firewall.AddBlocklistSet(setName, batch); err != nil {
			logger.Error("blocklist", "Failed to add blocklist batch",
				"name", name,
				"batch", fmt.Sprintf("%d-%d", i, end-1),
				"error", err.Error())
			// Continue with next batch despite error
		}

		time.Sleep(defaultBatchDelay)
	}
}

func (b *ExternalBlocklistManager) IsIPBlocked(ip net.IP) (bool, string) {
	// This should be implemented by querying your firewall's state
	// For example, if using nftables, you would check if IP exists in any blocklist set
	return false, ""
}

func (b *ExternalBlocklistManager) Stop() {
	close(b.stopCh)
	b.wg.Wait()
	logger.Info("blocklist", "External blocklist manager stopped")
}

func (b *ExternalBlocklistManager) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled":    b.config.EnableExternalBlocklists,
		"blocklists": len(b.blocklists),
		"active":     0,
		"total_ips":  0,
	}

	blocklistStats := make(map[string]interface{})
	activeCount := 0
	totalIPs := 0

	for name, blocklist := range b.blocklists {
		blocklistStats[name] = map[string]interface{}{
			"enabled":     blocklist.Enabled,
			"last_update": blocklist.LastUpdate,
			"ip_count":    blocklist.IPCount,
			"error_count": blocklist.ErrorCount,
			"source":      blocklist.URL,
		}
		if blocklist.Enabled {
			activeCount++
			totalIPs += blocklist.IPCount
		}
	}

	stats["blocklist_details"] = blocklistStats
	stats["active"] = activeCount
	stats["total_ips"] = totalIPs

	return stats
}

func (b *ExternalBlocklistManager) GetBlocklists() map[string]*Blocklist {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]*Blocklist, len(b.blocklists))
	for k, v := range b.blocklists {
		// Return a copy to avoid concurrent modification
		bl := *v
		result[k] = &bl
	}
	return result
}
