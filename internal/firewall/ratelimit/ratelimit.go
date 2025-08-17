// internal/firewall/ratelimit/ratelimit.go
package ratelimit

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	// Default configurations
	DefaultGlobalConnLimit = 1000
	DefaultPerIPConnLimit  = 100
	DefaultBurstSize       = 50
	DefaultTimeWindow      = time.Second
	DefaultCleanupInterval = 5 * time.Minute
	DefaultSetTimeout      = time.Hour

	// nftables names
	RateLimitChain        = "ratelimit_chain"
	RateLimitIPsSet       = "rate_limit_ips"
	RateLimitBannedSet    = "rate_limit_banned"
	RateLimitWhitelistSet = "rate_limit_whitelist"

	// Chain priorities
	RateLimitChainPriority = -150
)

// RateLimitManager manages rate limiting
type RateLimitManager struct {
	conn   *nftables.Conn
	table  *nftables.Table
	config *Config

	stats *RateLimitStats
	mu    sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds rate limiting configuration
type Config struct {
	EnableRateLimit    bool          `json:"enable_rate_limit"`
	GlobalConnLimit    int           `json:"global_conn_limit"`
	GlobalBurstSize    int           `json:"global_burst_size"`
	PerIPConnLimit     int           `json:"per_ip_conn_limit"`
	PerIPBurstSize     int           `json:"per_ip_burst_size"`
	PerIPTimeWindow    time.Duration `json:"per_ip_time_window"`
	HTTPRequestLimit   int           `json:"http_request_limit"`
	HTTPBurstSize      int           `json:"http_burst_size"`
	SSHConnLimit       int           `json:"ssh_conn_limit"`
	SSHBurstSize       int           `json:"ssh_burst_size"`
	EnableAutoBan      bool          `json:"enable_auto_ban"`
	BanThreshold       int           `json:"ban_threshold"`
	BanDuration        time.Duration `json:"ban_duration"`
	CleanupInterval    time.Duration `json:"cleanup_interval"`
	SetTimeout         time.Duration `json:"set_timeout"`
	WhitelistedIPs     []string      `json:"whitelisted_ips"`
	WhitelistedSubnets []string      `json:"whitelisted_subnets"`
}

// RateLimitStats tracks statistics
type RateLimitStats struct {
	TotalConnections int64     `json:"total_connections"`
	RateLimitedConns int64     `json:"rate_limited_connections"`
	BannedIPs        int       `json:"banned_ips"`
	WhitelistedIPs   int       `json:"whitelisted_ips"`
	HTTPRequests     int64     `json:"http_requests"`
	HTTPRateLimited  int64     `json:"http_rate_limited"`
	SSHConnections   int64     `json:"ssh_connections"`
	SSHRateLimited   int64     `json:"ssh_rate_limited"`
	LastCleanup      time.Time `json:"last_cleanup"`
	LastStatsUpdate  time.Time `json:"last_stats_update"`
}

// RuleType represents rule type
type RuleType int

const (
	RuleTypeGlobal RuleType = iota
	RuleTypePerIP
	RuleTypeHTTP
	RuleTypeSSH
	RuleTypeCustom
)

// RateLimitRule represents a rate limit rule
type RateLimitRule struct {
	Type       RuleType      `json:"type"`
	Name       string        `json:"name"`
	Rate       int           `json:"rate"`
	Burst      int           `json:"burst"`
	TimeWindow time.Duration `json:"time_window"`
	Protocol   string        `json:"protocol,omitempty"`
	Port       int           `json:"port,omitempty"`
	Enabled    bool          `json:"enabled"`
}

// NewRateLimitManager creates a new manager
func NewRateLimitManager(conn *nftables.Conn, table *nftables.Table, cfg *config.RateLimitConfig) *RateLimitManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &RateLimitManager{
		conn:   conn,
		table:  table,
		config: convertConfig(cfg),
		stats:  &RateLimitStats{},
		ctx:    ctx,
		cancel: cancel,
	}
}

func convertConfig(oldCfg *config.RateLimitConfig) *Config {
	if oldCfg == nil {
		return getDefaultConfig()
	}
	return &Config{
		EnableRateLimit:    oldCfg.EnableRateLimit,
		GlobalConnLimit:    getIntOrDefault(oldCfg.GlobalConnLimit, DefaultGlobalConnLimit),
		GlobalBurstSize:    DefaultBurstSize,
		PerIPConnLimit:     DefaultPerIPConnLimit,
		PerIPBurstSize:     DefaultBurstSize,
		PerIPTimeWindow:    DefaultTimeWindow,
		HTTPRequestLimit:   500,
		HTTPBurstSize:      100,
		SSHConnLimit:       10,
		SSHBurstSize:       5,
		EnableAutoBan:      true,
		BanThreshold:       5,
		BanDuration:        24 * time.Hour,
		CleanupInterval:    DefaultCleanupInterval,
		SetTimeout:         DefaultSetTimeout,
		WhitelistedIPs:     []string{},
		WhitelistedSubnets: []string{},
	}
}

func getDefaultConfig() *Config {
	return &Config{
		EnableRateLimit:    false,
		GlobalConnLimit:    DefaultGlobalConnLimit,
		GlobalBurstSize:    DefaultBurstSize,
		PerIPConnLimit:     DefaultPerIPConnLimit,
		PerIPBurstSize:     DefaultBurstSize,
		PerIPTimeWindow:    DefaultTimeWindow,
		HTTPRequestLimit:   500,
		HTTPBurstSize:      100,
		SSHConnLimit:       10,
		SSHBurstSize:       5,
		EnableAutoBan:      true,
		BanThreshold:       5,
		BanDuration:        24 * time.Hour,
		CleanupInterval:    DefaultCleanupInterval,
		SetTimeout:         DefaultSetTimeout,
		WhitelistedIPs:     []string{},
		WhitelistedSubnets: []string{},
	}
}

func getIntOrDefault(value, defaultValue int) int {
	if value <= 0 {
		return defaultValue
	}
	return value
}

// Initialize creates nftables sets and starts background tasks
func (r *RateLimitManager) Initialize() error {
	if !r.config.EnableRateLimit {
		logger.Info("ratelimit", "Rate limiting disabled")
		return nil
	}

	logger.Info("ratelimit", "Initializing rate limiting",
		"global_limit", r.config.GlobalConnLimit,
		"per_ip_limit", r.config.PerIPConnLimit,
		"auto_ban", r.config.EnableAutoBan)

	if err := r.createNFTablesSets(); err != nil {
		return fmt.Errorf("failed to create sets: %w", err)
	}

	if err := r.initializeWhitelistedIPs(); err != nil {
		logger.Warn("ratelimit", "Failed to init whitelisted IPs", "error", err.Error())
	}

	r.startBackgroundTasks()
	return nil
}

func (r *RateLimitManager) createNFTablesSets() error {
	sets := []struct {
		name     string
		keyType  nftables.SetDatatype
		interval bool
		timeout  time.Duration
		dynamic  bool
	}{
		{
			name:     RateLimitIPsSet,
			keyType:  nftables.TypeIPAddr,
			interval: true,
			timeout:  r.config.SetTimeout,
			dynamic:  true,
		},
		{
			name:     RateLimitBannedSet,
			keyType:  nftables.TypeIPAddr,
			interval: true,
			timeout:  r.config.BanDuration,
			dynamic:  true,
		},
		{
			name:     RateLimitWhitelistSet,
			keyType:  nftables.TypeIPAddr,
			interval: true,
			timeout:  0, // permanent
			dynamic:  false,
		},
	}

	for _, cfg := range sets {
		set := &nftables.Set{
			Name:     cfg.name,
			Table:    r.table,
			KeyType:  cfg.keyType,
			Interval: cfg.interval,
			Dynamic:  cfg.dynamic,
		}

		if cfg.timeout > 0 {
			set.Timeout = cfg.timeout
		}

		if err := r.conn.AddSet(set, nil); err != nil {
			return fmt.Errorf("failed to create set %s: %w", cfg.name, err)
		}

		logger.Info("ratelimit", "Created nftables set",
			"name", cfg.name,
			"timeout", cfg.timeout,
			"dynamic", cfg.dynamic)
	}
	return nil
}

// initializeWhitelistedIPs adds whitelist IPs and subnets
func (r *RateLimitManager) initializeWhitelistedIPs() error {
	if len(r.config.WhitelistedIPs) == 0 && len(r.config.WhitelistedSubnets) == 0 {
		return nil
	}

	set := &nftables.Set{Name: RateLimitWhitelistSet, Table: r.table}
	var elements []nftables.SetElement

	for _, ipStr := range r.config.WhitelistedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			logger.Warn("ratelimit", "Invalid whitelisted IP", "ip", ipStr)
			continue
		}
		elements = append(elements, nftables.SetElement{Key: ip.To4()})
	}

	for _, subnetStr := range r.config.WhitelistedSubnets {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err != nil {
			logger.Warn("ratelimit", "Invalid whitelisted subnet", "subnet", subnetStr, "error", err.Error())
			continue
		}
		elements = append(elements, nftables.SetElement{
			Key:    subnet.IP.To4(),
			KeyEnd: r.getSubnetEnd(subnet),
		})
	}

	if len(elements) > 0 {
		r.conn.SetAddElements(set, elements)
		r.mu.Lock()
		r.stats.WhitelistedIPs = len(elements)
		r.mu.Unlock()

		logger.Info("ratelimit", "Added whitelisted IPs", "count", len(elements))
	}

	return nil
}

func (r *RateLimitManager) getSubnetEnd(subnet *net.IPNet) []byte {
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)
	for i := range ip {
		ip[i] |= ^subnet.Mask[i]
	}
	return ip.To4()
}

// startBackgroundTasks runs cleanup and stats updates
func (r *RateLimitManager) startBackgroundTasks() {
	r.wg.Add(2)
	go r.runCleanupTask()
	go r.runStatsUpdateTask()
}

func (r *RateLimitManager) runCleanupTask() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.config.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.performCleanup()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RateLimitManager) runStatsUpdateTask() {
	defer r.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.updateStats()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RateLimitManager) performCleanup() {
	logger.Info("ratelimit", "Performing cleanup")
	r.mu.Lock()
	r.stats.LastCleanup = time.Now()
	r.mu.Unlock()
	logger.Info("ratelimit", "Cleanup completed")
}

func (r *RateLimitManager) updateStats() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.LastStatsUpdate = time.Now()
}

// Stop stops the manager
func (r *RateLimitManager) Stop() {
	r.cancel()
	r.wg.Wait()
	logger.Info("ratelimit", "RateLimitManager stopped")
}

// BanIP bans an IP for a duration
func (r *RateLimitManager) BanIP(ip net.IP, duration time.Duration) error {
	if !r.config.EnableRateLimit || !r.config.EnableAutoBan {
		return fmt.Errorf("auto-ban is disabled")
	}

	element := nftables.SetElement{
		Key:     ip.To4(),
		Timeout: duration,
	}

	set := &nftables.Set{
		Name:  RateLimitBannedSet,
		Table: r.table,
	}

	if err := r.conn.SetAddElements(set, []nftables.SetElement{element}); err != nil {
		return fmt.Errorf("failed to add IP to banned set: %w", err)
	}

	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush changes: %w", err)
	}

	r.mu.Lock()
	r.stats.BannedIPs++
	r.mu.Unlock()

	logger.Info("ratelimit", "Banned IP", "ip", ip.String(), "duration", duration)
	return nil
}

// UnbanIP removes an IP from banned set
func (r *RateLimitManager) UnbanIP(ip net.IP) error {
	set := &nftables.Set{
		Name:  RateLimitBannedSet,
		Table: r.table,
	}
	element := nftables.SetElement{Key: ip.To4()}

	if err := r.conn.SetDeleteElements(set, []nftables.SetElement{element}); err != nil {
		return fmt.Errorf("failed to remove IP from banned set: %w", err)
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush changes: %w", err)
	}

	r.mu.Lock()
	if r.stats.BannedIPs > 0 {
		r.stats.BannedIPs--
	}
	r.mu.Unlock()

	logger.Info("ratelimit", "Unbanned IP", "ip", ip.String())
	return nil
}

// GetStats returns a copy of current stats
func (r *RateLimitManager) GetStats() *RateLimitStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copy := *r.stats
	return &copy
}

// UpdateConfig updates configuration
func (r *RateLimitManager) UpdateConfig(cfg *Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = cfg
	logger.Info("ratelimit", "Configuration updated")
}

// IsEnabled returns if rate limiting is enabled
func (r *RateLimitManager) IsEnabled() bool {
	return r.config.EnableRateLimit
}

// AddRateLimitRules adds the necessary nftables rules for rate limiting
func (r *RateLimitManager) AddRateLimitRules(inputChain *nftables.Chain) error {
	if !r.config.EnableRateLimit {
		return nil
	}

	// 1. Create a dedicated chain for rate limiting
	rateLimitChain := &nftables.Chain{
		Name:  RateLimitChain,
		Table: r.table,
	}
	r.conn.AddChain(rateLimitChain)

	// 2. Add a rule to the input chain to jump to our new chain
	r.conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// We only want to rate limit new connections
			&expr.Ct{Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x01}, // NEW
				Xor:            []byte{0x00},
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x01}},
			&expr.Verdict{Kind: expr.VerdictJump, Chain: RateLimitChain},
		},
	})

	// 3. Add rules to the rate limit chain
	// Rule: Whitelisted IPs are not rate limited
	r.conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: rateLimitChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: RateLimitWhitelistSet},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule: Banned IPs are dropped
	r.conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: rateLimitChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: RateLimitBannedSet},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule: Per-IP rate limiting
	if r.config.PerIPConnLimit > 0 {
		r.conn.AddRule(&nftables.Rule{
			Table: r.table,
			Chain: rateLimitChain,
			Exprs: []expr.Any{
				&expr.Meter{
					Name:     RateLimitIPsSet,
					Key:      &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
					Rate:     uint64(r.config.PerIPConnLimit),
					RateUnit: nftables.RateUnitPackets,
					Burst:    uint32(r.config.PerIPBurstSize),
					Interval: r.config.PerIPTimeWindow,
					Over: &expr.StatementBlock{
						Exprs: []expr.Any{
							// If rate is exceeded, add to the banned set
							&expr.Dynamic{
								Name: RateLimitBannedSet,
								Op:   expr.DynamicOpAdd,
								Set:  true,
								Expr: &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
							},
							&expr.Verdict{Kind: expr.VerdictDrop},
						},
					},
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	logger.Info("ratelimit", "Added rate limit rules to nftables")
	return nil
}
