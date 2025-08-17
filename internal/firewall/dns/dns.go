// internal/firewall/dns/dns.go
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"qff/internal/logger"

	"github.com/google/nftables"
)

const (
	MaxConcurrentResolves = 10
)

const (
	SetNamePrefix = "qff_dns_" 
)

// DNSManager handles dynamic DNS resolution for nftables sets
type DNSManager struct {
	// Core components
	conn  *nftables.Conn
	table *nftables.Table

	// State management
	hostnames map[string]*HostEntry
	mu        sync.RWMutex

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Configuration
	config *Config
}

// Config holds configuration for the DNS manager
type Config struct {
	UpdateInterval time.Duration
	ResolveTimeout time.Duration
	MaxRetries     int
	RetryBackoff   time.Duration
}

// HostEntry represents a hostname and its resolved IPs
type HostEntry struct {
	Hostname    string    `json:"hostname"`
	IPs         []net.IP  `json:"ips"`
	SetName     string    `json:"set_name"`
	LastCheck   time.Time `json:"last_check"`
	LastSuccess time.Time `json:"last_success"`
	ErrorCount  int       `json:"error_count"`
	LastError   string    `json:"last_error,omitempty"`
}

// DNSStats provides statistics about DNS resolution
type DNSStats struct {
	TotalHostnames     int           `json:"total_hostnames"`
	SuccessfulChecks   int64         `json:"successful_checks"`
	FailedChecks       int64         `json:"failed_checks"`
	LastUpdateTime     time.Time     `json:"last_update_time"`
	AverageResolveTime time.Duration `json:"average_resolve_time"`
}

func NewDNSManager(conn *nftables.Conn, table *nftables.Table, config *Config) *DNSManager {
	// Defaults are now handled by the main config loader
	ctx, cancel := context.WithCancel(context.Background())
	return &DNSManager{
		conn:      conn,
		table:     table,
		hostnames: make(map[string]*HostEntry),
		ctx:       ctx,
		cancel:    cancel,
		config:    config,
	}
}

func (d *DNSManager) Initialize() error {
	logger.Info("dns", "Initializing Dynamic DNS manager",
		"update_interval", d.config.UpdateInterval,
		"resolve_timeout", d.config.ResolveTimeout)

	// Start the DNS updater goroutine
	d.wg.Add(1)
	go d.runDNSUpdater()

	return nil
}

func (d *DNSManager) AddHostname(hostname, setType string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	// Validate hostname format
	if err := d.validateHostname(hostname); err != nil {
		return fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if hostname already exists
	if _, exists := d.hostnames[hostname]; exists {
		logger.Info("dns", "Hostname already managed", "hostname", hostname)
		return nil
	}

	setName := d.GenerateSetName(hostname)

	// Create nftables set
	set := &nftables.Set{
		Name:    setName,
		Table:   d.table,
		KeyType: nftables.TypeIPAddr,
	}

	if err := d.conn.AddSet(set, []nftables.SetElement{}); err != nil {
		return fmt.Errorf("failed to create nftables set %q: %w", setName, err)
	}

	entry := &HostEntry{
		Hostname:    hostname,
		SetName:     setName,
		IPs:         make([]net.IP, 0),
		LastCheck:   time.Time{},
		LastSuccess: time.Time{},
	}

	d.hostnames[hostname] = entry

	// Perform initial resolution
	go func() {
		if err := d.resolveHostnameWithRetry(entry); err != nil {
			logger.Error("dns", "Initial hostname resolution failed",
				"hostname", hostname, "error", err.Error())
		}
	}()

	logger.Info("dns", "Added dynamic hostname", "hostname", hostname, "set", setName)
	return nil
}

func (d *DNSManager) RemoveHostname(hostname string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	entry, exists := d.hostnames[hostname]
	if !exists {
		return fmt.Errorf("hostname %q not found", hostname)
	}

	// Remove the nftables set
	set := &nftables.Set{Name: entry.SetName, Table: d.table}
	d.conn.DelSet(set)

	delete(d.hostnames, hostname)

	logger.Info("dns", "Removed dynamic hostname", "hostname", hostname)
	return nil
}

func (d *DNSManager) runDNSUpdater() {
	defer d.wg.Done()

	ticker := time.NewTicker(d.config.UpdateInterval)
	defer ticker.Stop()

	// Perform initial update
	d.updateAllHostnames()

	for {
		select {
		case <-ticker.C:
			d.updateAllHostnames()
		case <-d.ctx.Done():
			logger.Info("dns", "DNS updater stopping")
			return
		}
	}
}

func (d *DNSManager) updateAllHostnames() {
	startTime := time.Now()

	// Get snapshot of hostnames to avoid holding lock during resolution
	d.mu.RLock()
	entries := make([]*HostEntry, 0, len(d.hostnames))
	for _, entry := range d.hostnames {
		entries = append(entries, entry)
	}
	d.mu.RUnlock()

	if len(entries) == 0 {
		return
	}

	logger.Info("dns", "Starting DNS update cycle", "hostnames", len(entries))

	// Use worker pool for concurrent resolution
	d.resolveHostnamesConcurrently(entries)

	// Flush all changes at once for better performance
	if err := d.conn.Flush(); err != nil {
		logger.Error("dns", "Failed to flush nftables changes", "error", err.Error())
	}

	duration := time.Since(startTime)
	logger.Info("dns", "DNS update cycle completed",
		"duration", duration, "hostnames", len(entries))
}

func (d *DNSManager) resolveHostnamesConcurrently(entries []*HostEntry) {
	// Use buffered channel to limit concurrent resolutions
	semaphore := make(chan struct{}, MaxConcurrentResolves)
	var wg sync.WaitGroup

	for _, entry := range entries {
		wg.Add(1)
		go func(e *HostEntry) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			if err := d.resolveHostnameWithRetry(e); err != nil {
				logger.Error("dns", "Failed to resolve hostname",
					"hostname", e.Hostname, "error", err.Error())
			}
		}(entry)
	}

	wg.Wait()
}

func (d *DNSManager) resolveHostnameWithRetry(entry *HostEntry) error {
	var lastErr error

	for attempt := 0; attempt < d.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := d.config.RetryBackoff * time.Duration(1<<uint(attempt-1))
			if backoff > time.Minute {
				backoff = time.Minute
			}

			select {
			case <-time.After(backoff):
			case <-d.ctx.Done():
				return d.ctx.Err()
			}
		}

		if err := d.resolveHostname(entry); err != nil {
			lastErr = err
			logger.Warn("dns", "DNS resolution attempt failed",
				"hostname", entry.Hostname, "attempt", attempt+1, "error", err.Error())
			continue
		}

		// Success
		d.mu.Lock()
		entry.ErrorCount = 0
		entry.LastError = ""
		entry.LastSuccess = time.Now()
		d.mu.Unlock()

		return nil
	}

	// All retries failed
	d.mu.Lock()
	entry.ErrorCount++
	entry.LastError = lastErr.Error()
	d.mu.Unlock()

	return fmt.Errorf("failed after %d attempts: %w", d.config.MaxRetries, lastErr)
}

func (d *DNSManager) resolveHostname(entry *HostEntry) error {
	ctx, cancel := context.WithTimeout(d.ctx, d.config.ResolveTimeout)
	defer cancel()

	// Use custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: d.config.ResolveTimeout,
			}
			return dialer.DialContext(ctx, network, address)
		},
	}

	ips, err := resolver.LookupIPAddr(ctx, entry.Hostname)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}

	// Extract IPv4 addresses and sort for consistent comparison
	var ipv4s []net.IP
	for _, ip := range ips {
		if ipv4 := ip.IP.To4(); ipv4 != nil {
			ipv4s = append(ipv4s, ipv4)
		}
	}

	// Sort IPs for consistent comparison
	sort.Slice(ipv4s, func(i, j int) bool {
		return ipv4s[i].String() < ipv4s[j].String()
	})

	d.mu.Lock()
	entry.LastCheck = time.Now()

	// Check if IPs have changed
	if d.ipsEqual(entry.IPs, ipv4s) {
		d.mu.Unlock()
		return nil // No change needed
	}

	oldCount := len(entry.IPs)
	entry.IPs = ipv4s
	d.mu.Unlock()

	logger.Info("dns", "Hostname IPs changed",
		"hostname", entry.Hostname,
		"old_count", oldCount,
		"new_count", len(ipv4s),
		"ips", d.formatIPs(ipv4s))

	// Update nftables set
	return d.updateNFTablesSet(entry, ipv4s)
}

func (d *DNSManager) updateNFTablesSet(entry *HostEntry, ips []net.IP) error {
	set := &nftables.Set{Name: entry.SetName, Table: d.table}

	// Clear existing elements
	d.conn.FlushSet(set)

	// Add new elements
	if len(ips) > 0 {
		elements := make([]nftables.SetElement, len(ips))
		for i, ip := range ips {
			elements[i] = nftables.SetElement{Key: ip}
		}

		d.conn.SetAddElements(set, elements)
	}

	return nil
}

func (d *DNSManager) ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}

	// Both slices should be sorted for accurate comparison
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}

	return true
}

func (d *DNSManager) formatIPs(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

func (d *DNSManager) validateHostname(hostname string) error {
	if len(hostname) == 0 || len(hostname) > 253 {
		return fmt.Errorf("hostname length must be 1-253 characters")
	}

	// Basic hostname validation
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return fmt.Errorf("hostname cannot start or end with a dot")
	}

	// Check for invalid characters
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '.') {
			return fmt.Errorf("hostname contains invalid character: %c", char)
		}
	}

	return nil
}

func (d *DNSManager) GenerateSetName(hostname string) string {
	// Replace dots and other special characters with underscores
	setName := strings.ReplaceAll(hostname, ".", "_")
	setName = strings.ReplaceAll(setName, "-", "_")

	// Ensure it starts with the prefix
	return SetNamePrefix + setName
}

// GetHostnames returns a copy of all managed hostnames
func (d *DNSManager) GetHostnames() map[string]*HostEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]*HostEntry, len(d.hostnames))
	for k, v := range d.hostnames {
		// Create a copy to avoid race conditions
		entryCopy := &HostEntry{
			Hostname:    v.Hostname,
			IPs:         make([]net.IP, len(v.IPs)),
			SetName:     v.SetName,
			LastCheck:   v.LastCheck,
			LastSuccess: v.LastSuccess,
			ErrorCount:  v.ErrorCount,
			LastError:   v.LastError,
		}
		copy(entryCopy.IPs, v.IPs)
		result[k] = entryCopy
	}

	return result
}

// GetHostnameByName returns a specific hostname entry
func (d *DNSManager) GetHostnameByName(hostname string) (*HostEntry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	entry, exists := d.hostnames[hostname]
	if !exists {
		return nil, false
	}

	// Return a copy
	entryCopy := &HostEntry{
		Hostname:    entry.Hostname,
		IPs:         make([]net.IP, len(entry.IPs)),
		SetName:     entry.SetName,
		LastCheck:   entry.LastCheck,
		LastSuccess: entry.LastSuccess,
		ErrorCount:  entry.ErrorCount,
		LastError:   entry.LastError,
	}
	copy(entryCopy.IPs, entry.IPs)

	return entryCopy, true
}

// GetStats returns statistics about DNS resolution
func (d *DNSManager) GetStats() *DNSStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := &DNSStats{
		TotalHostnames: len(d.hostnames),
	}

	var totalResolveTime time.Duration
	var resolveCount int

	for _, entry := range d.hostnames {
		if !entry.LastSuccess.IsZero() {
			stats.SuccessfulChecks++
		}
		if entry.ErrorCount > 0 {
			stats.FailedChecks += int64(entry.ErrorCount)
		}
		if !entry.LastCheck.IsZero() {
			if stats.LastUpdateTime.Before(entry.LastCheck) {
				stats.LastUpdateTime = entry.LastCheck
			}
			resolveCount++
		}
	}

	if resolveCount > 0 {
		stats.AverageResolveTime = totalResolveTime / time.Duration(resolveCount)
	}

	return stats
}

// ForceUpdate immediately updates all hostnames
func (d *DNSManager) ForceUpdate() error {
	logger.Info("dns", "Forcing DNS update for all hostnames")
	go d.updateAllHostnames()
	return nil
}

// Stop gracefully shuts down the DNS manager
func (d *DNSManager) Stop() error {
	logger.Info("dns", "Stopping DNS manager")

	d.cancel()  // Cancel context to stop background goroutines
	d.wg.Wait() // Wait for all goroutines to finish

	logger.Info("dns", "DNS manager stopped")
	return nil
}
