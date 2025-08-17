// internal/firewall/nftables.go
package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"syscall" // +++ ADD THIS LINE +++

	"qff/internal/config"
	"qff/internal/firewall/dns" 
	"qff/internal/logger"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// getDockerInterfaces returns a list of Docker-related network interface names.
func (n *NFTManager) getDockerInterfaces() ([]string, error) {
	var dockerInterfaces []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range interfaces {
		if i.Name == "docker0" || strings.HasPrefix(i.Name, "br-") {
			dockerInterfaces = append(dockerInterfaces, i.Name)
		}
	}
	return dockerInterfaces, nil
}

// RuleKey uniquely identifies a port rule
type RuleKey struct {
	Port      int
	Protocol  string
	Direction string
	Action    string
}

// RuleTracker stores references to nftables rules
type RuleTracker struct {
	Rule    *nftables.Rule
	Key     RuleKey
	AddedAt time.Time
}

type RateLimitManager struct {
	conn   *nftables.Conn
	table  *nftables.Table
	config *config.RateLimitConfig
}

type BOGONManager struct {
	config *config.SecurityConfig
	conn   *nftables.Conn
	table  *nftables.Table
}

type NFTManager struct {
	conn        *nftables.Conn
	config      *config.Config
	table       *nftables.Table
	dnsManager  *dns.DNSManager // Correctly typed
	rateLimiter *RateLimitManager
	bogonMgr    *BOGONManager

	// Rule tracking
	trackedRules    map[RuleKey]*RuleTracker
	blocklistRules  map[string]*nftables.Rule // Tracks rules for dynamic blocklists
	rulesMutex      sync.RWMutex
}

type FirewallState struct {
	Ruleset []byte `json:"ruleset"`
}

func NewRateLimitManager(conn *nftables.Conn, table *nftables.Table, cfg *config.RateLimitConfig) *RateLimitManager {
	return &RateLimitManager{
		conn:   conn,
		table:  table,
		config: cfg,
	}
}

func NewBOGONManager(cfg *config.SecurityConfig, conn *nftables.Conn, table *nftables.Table) *BOGONManager {
	return &BOGONManager{
		config: cfg,
		conn:   conn,
		table:  table,
	}
}

func NewNFTManager(cfg *config.Config) *NFTManager {
	conn := &nftables.Conn{}
	table := &nftables.Table{
		Name:   "qff",
		Family: nftables.TableFamilyINet,
	}

	mgr := &NFTManager{
		conn:           conn,
		config:         cfg,
		table:          table,
		trackedRules:   make(map[RuleKey]*RuleTracker),
		blocklistRules: make(map[string]*nftables.Rule),
	}

	// Properly initialize the DNS Manager with its configuration
	dnsConfig := &dns.Config{
		UpdateInterval: cfg.DNS.UpdateInterval,
	}
	mgr.dnsManager = dns.NewDNSManager(conn, table, dnsConfig)

	mgr.rateLimiter = NewRateLimitManager(conn, table, &cfg.RateLimit)
	mgr.bogonMgr = NewBOGONManager(&cfg.Security, conn, table)

	return mgr
}

// Simplified methods for the sub-managers
func (r *RateLimitManager) Initialize() error {
	if !r.config.EnableRateLimit {
		return nil
	}
	logger.Info("ratelimit", "Initializing rate limiting")
	return nil
}

func (r *RateLimitManager) AddRateLimitRules(inputChain *nftables.Chain) error {
	if !r.config.EnableRateLimit {
		return nil
	}
	logger.Info("ratelimit", "Adding rate limit rules")
	return nil
}

func (b *BOGONManager) Initialize() error {
	if !b.config.EnableBogonFilter {
		return nil
	}
	logger.Info("bogon", "Initializing BOGON filtering")
	return nil
}

func (b *BOGONManager) AddBOGONRules(inputChain *nftables.Chain) error {
	if !b.config.EnableBogonFilter {
		return nil
	}
	logger.Info("bogon", "Adding BOGON rules")
	return nil
}

// Utility functions
func CheckNFTablesAvailable() error {
	// Try to create a test connection
	conn := &nftables.Conn{}

	// Try to list existing tables - this will fail if nftables is not available
	_, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables is not available or not installed.\nPlease install nftables first:\n"+
			"  Ubuntu/Debian: sudo apt install nftables\n"+
			"  RHEL/CentOS:   sudo yum install nftables\n"+
			"  Arch Linux:    sudo pacman -S nftables\n"+
			"Error: %v", err)
	}

	return nil
}

// NFTManager methods
func (n *NFTManager) AddPortRule(port int, protocol string, direction string, action string) error {
	var chain *nftables.Chain
	var protocolNum byte

	// Determine protocol number
	switch strings.ToLower(protocol) {
	case "tcp":
		protocolNum = 6
	case "udp":
		protocolNum = 17
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Determine chain
	switch strings.ToLower(direction) {
	case "input", "in":
		chain = &nftables.Chain{Name: "input", Table: n.table}
	case "output", "out":
		chain = &nftables.Chain{Name: "output", Table: n.table}
	default:
		return fmt.Errorf("unsupported direction: %s", direction)
	}

	// Determine verdict and log prefix
	var verdict expr.VerdictKind
	var logPrefix string
	switch strings.ToLower(action) {
	case "accept", "allow":
		verdict = expr.VerdictAccept
		logPrefix = fmt.Sprintf("QFF-ACCEPT-%s-%d: ", strings.ToUpper(direction), port)
	case "drop", "deny", "block":
		verdict = expr.VerdictDrop
		logPrefix = fmt.Sprintf("QFF-DROP-%s-%d: ", strings.ToUpper(direction), port)
	case "reject":
		verdict = expr.VerdictReturn
		logPrefix = fmt.Sprintf("QFF-REJECT-%s-%d: ", strings.ToUpper(direction), port)
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}

	// Create the rule with logging
	rule := &nftables.Rule{
		Table: n.table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNum}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Log{Data: []byte(logPrefix)},
			&expr.Verdict{Kind: verdict},
		},
	}

	// Add the rule
	n.conn.AddRule(rule)

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Track the rule
	key := RuleKey{
		Port:      port,
		Protocol:  strings.ToLower(protocol),
		Direction: strings.ToLower(direction),
		Action:    strings.ToLower(action),
	}

	n.rulesMutex.Lock()
	n.trackedRules[key] = &RuleTracker{
		Rule:    rule,
		Key:     key,
		AddedAt: time.Now(),
	}
	n.rulesMutex.Unlock()

	logger.Info("firewall", "Added port rule with logging", "port", port, "protocol", protocol, "direction", direction, "action", action)
	return nil
}

func (n *NFTManager) RemovePortRule(port int, protocol string, direction string) error {
	// Normalize inputs
	protocol = strings.ToLower(protocol)
	direction = strings.ToLower(direction)

	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	// Find all rules matching port, protocol, and direction (regardless of action)
	var rulesToRemove []*RuleTracker
	var keysToRemove []RuleKey

	for key, tracker := range n.trackedRules {
		if key.Port == port && key.Protocol == protocol && key.Direction == direction {
			rulesToRemove = append(rulesToRemove, tracker)
			keysToRemove = append(keysToRemove, key)
		}
	}

	if len(rulesToRemove) == 0 {
		return fmt.Errorf("no matching rule found for port %d/%s %s", port, protocol, direction)
	}

	// Remove rules from nftables
	for _, tracker := range rulesToRemove {
		n.conn.DelRule(tracker.Rule)
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Remove from tracking
	for _, key := range keysToRemove {
		delete(n.trackedRules, key)
	}

	logger.Info("firewall", "Removed port rules", "port", port, "protocol", protocol, "direction", direction, "count", len(rulesToRemove))
	return nil
}

func (n *NFTManager) ListPortRules() map[string]interface{} {
	n.rulesMutex.RLock()
	defer n.rulesMutex.RUnlock()

	// Get config-based rules
	configRules := map[string]interface{}{
		"tcp_in":  n.config.Ports.TCPIn,
		"tcp_out": n.config.Ports.TCPOut,
		"udp_in":  n.config.Ports.UDPIn,
		"udp_out": n.config.Ports.UDPOut,
	}

	// Add dynamically tracked rules
	dynamicRules := make(map[string]interface{})
	for key, tracker := range n.trackedRules {
		ruleID := fmt.Sprintf("%s_%d_%s_%s", key.Protocol, key.Port, key.Direction, key.Action)
		dynamicRules[ruleID] = map[string]interface{}{
			"port":      key.Port,
			"protocol":  key.Protocol,
			"direction": key.Direction,
			"action":    key.Action,
			"added_at":  tracker.AddedAt,
		}
	}

	return map[string]interface{}{
		"config_rules":  configRules,
		"dynamic_rules": dynamicRules,
		"total_tracked": len(n.trackedRules),
	}
}

// RemoveAllPortRules removes all tracked port rules
func (n *NFTManager) RemoveAllPortRules() error {
	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	for _, tracker := range n.trackedRules {
		n.conn.DelRule(tracker.Rule)
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Clear tracking
	n.trackedRules = make(map[RuleKey]*RuleTracker)

	logger.Info("firewall", "Removed all tracked port rules")
	return nil
}

// GetRuleStats returns statistics about tracked rules
func (n *NFTManager) GetRuleStats() map[string]interface{} {
	n.rulesMutex.RLock()
	defer n.rulesMutex.RUnlock()

	stats := map[string]interface{}{
		"total_tracked": len(n.trackedRules),
	}

	// Count by protocol
	protocolCount := make(map[string]int)
	directionCount := make(map[string]int)
	actionCount := make(map[string]int)

	for key := range n.trackedRules {
		protocolCount[key.Protocol]++
		directionCount[key.Direction]++
		actionCount[key.Action]++
	}

	stats["by_protocol"] = protocolCount
	stats["by_direction"] = directionCount
	stats["by_action"] = actionCount

	return stats
}

// UpdatePortRuleAction changes the action of an existing rule
func (n *NFTManager) UpdatePortRuleAction(port int, protocol string, direction string, newAction string) error {
	// Remove the old rule
	if err := n.RemovePortRule(port, protocol, direction); err != nil {
		return fmt.Errorf("failed to remove old rule: %w", err)
	}

	// Add the new rule with updated action
	if err := n.AddPortRule(port, protocol, direction, newAction); err != nil {
		return fmt.Errorf("failed to add updated rule: %w", err)
	}

	return nil
}

func (n *NFTManager) Initialize() error {
	if err := n.FlushRuleset(); err != nil {
		return fmt.Errorf("failed to flush ruleset on startup: %w", err)
	}

	logger.Info("firewall", "Initializing nftables")

	n.conn.AddTable(n.table)

	if err := n.setupChains(); err != nil {
		return fmt.Errorf("failed to setup chains: %w", err)
	}

	if err := n.setupSets(); err != nil {
		return fmt.Errorf("failed to setup sets: %w", err)
	}

	if err := n.setupRules(); err != nil {
		return fmt.Errorf("failed to setup rules: %w", err)
	}

	if err := n.setupDockerRules(); err != nil {
		return fmt.Errorf("failed to setup Docker rules: %w", err)
	}

	// Initialize sub-managers and their rules
	if err := n.dnsManager.Initialize(); err != nil {
		logger.Error("firewall", "DNS manager initialization failed", "error", err.Error())
	}
	if err := n.setupDynamicDNSRules(); err != nil {
		logger.Error("firewall", "Failed to set up dynamic DNS rules", "error", err.Error())
	}

	if err := n.rateLimiter.Initialize(); err != nil {
		logger.Error("firewall", "Rate limiter initialization failed", "error", err.Error())
	}

	if err := n.bogonMgr.Initialize(); err != nil {
		logger.Error("firewall", "BOGON manager initialization failed", "error", err.Error())
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	logger.Info("firewall", "nftables initialized successfully")
	return nil
}

func (n *NFTManager) setupChains() error {
	chains := []struct {
		name     string
		hook     *nftables.ChainHook
		priority *nftables.ChainPriority
		policy   nftables.ChainPolicy
	}{
		{"input", nftables.ChainHookInput, nftables.ChainPriorityFilter, n.getDefaultPolicy()},
		{"output", nftables.ChainHookOutput, nftables.ChainPriorityFilter, nftables.ChainPolicyDrop},
		{"forward", nftables.ChainHookForward, nftables.ChainPriorityFilter, nftables.ChainPolicyDrop},
	}

	for _, c := range chains {
		n.conn.AddChain(&nftables.Chain{
			Name:     c.name,
			Table:    n.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  c.hook,
			Priority: c.priority,
			Policy:   &c.policy,
		})
	}

	return nil
}

func (n *NFTManager) getDefaultPolicy() nftables.ChainPolicy {
	if n.config.Firewall.DefaultPolicy == "accept" {
		return nftables.ChainPolicyAccept
	}
	return nftables.ChainPolicyDrop
}

func (n *NFTManager) setupSets() error {
	sets := []struct {
		name    string
		keyType nftables.SetDatatype
	}{
		{"whitelist_ips", nftables.TypeIPAddr},
		{"blacklist_ips", nftables.TypeIPAddr},
		{"temp_block_ips", nftables.TypeIPAddr},
	}

	for _, s := range sets {
		n.conn.AddSet(&nftables.Set{
			Name:    s.name,
			Table:   n.table,
			KeyType: s.keyType,
		}, []nftables.SetElement{})
	}

	return nil
}

func (n *NFTManager) setupRules() error {
    inputChain := &nftables.Chain{Name: "input", Table: n.table}
	outputChain := &nftables.Chain{Name: "output", Table: n.table}

	// Allow established and related outbound connections
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: outputChain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x02 | 0x04}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// 2a. SYN Flood Protection
	if n.config.SynFlood.EnableProtection {
		// This rule matches new TCP packets with only the SYN flag set,
		// and applies a rate limit to them.
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				// Match TCP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},

				// Match TCP flags: SYN set, ACK/RST/FIN clear
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            1,
					Mask:           []byte{0x16}, // SYN, ACK, RST, FIN
					Xor:            []byte{0x00},
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}}, // Must equal SYN

				// Apply a simple rate limit
				&expr.Limit{
					Rate:  uint64(n.config.SynFlood.SynRateLimit),
					Burst: uint32(n.config.SynFlood.SynBurst),
				},
				// If the rate is NOT exceeded, accept the packet and stop processing rules.
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		logger.Info("firewall", "Enabled SYN flood protection", "rate", n.config.SynFlood.SynRateLimit, "burst", n.config.SynFlood.SynBurst)
	}

    // 1. ACCEPT ESTABLISHED, RELATED (Highest Priority)
    // Keep stateful connections flowing without re-evaluation.
    n.conn.AddRule(&nftables.Rule{
        Table: n.table,
        Chain: inputChain,
        Exprs: []expr.Any{
            &expr.Ct{Key: expr.CtKeySTATE},
            &expr.Bitwise{
                SourceRegister: 1,
                DestRegister:   1,
                Len:            4,
                Mask:           []byte{0x02 | 0x04}, // ESTABLISHED | RELATED
                Xor:            []byte{0x00},
            },
            &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })

    // 2. DROP INVALID (Early Sanity Check)
    // Drop malformed packets immediately.
    n.conn.AddRule(&nftables.Rule{
        Table: n.table,
        Chain: inputChain,
        Exprs: []expr.Any{
            &expr.Ct{Key: expr.CtKeySTATE},
            &expr.Bitwise{
                SourceRegister: 1,
                DestRegister:   1,
                Len:            4,
                Mask:           []byte{0x08}, // INVALID
                Xor:            []byte{0x00},
            },
            &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x08}},
            &expr.Log{Data: []byte("QFF-DROP-INVALID: ")},
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // 3. ACCEPT LOOPBACK
    // Always allow local traffic.
    n.conn.AddRule(&nftables.Rule{
        Table: n.table,
        Chain: inputChain,
        Exprs: []expr.Any{
            &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
            &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })

	// 3a. ICMP Flood Protection
	if n.config.Security.EnableICMPFloodProtection && n.config.Security.ICMPFloodRate != "" {
		rate, burst, err := parseRateLimit(n.config.Security.ICMPFloodRate)
		if err != nil {
			logger.Warn("firewall", "Invalid ICMP flood rate, skipping rule", "value", n.config.Security.ICMPFloodRate, "error", err)
		} else {
			n.conn.AddRule(&nftables.Rule{
				Table: n.table,
				Chain: inputChain,
				Exprs: []expr.Any{
					// Match ICMP protocol
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_ICMP}},
					// Match ICMP type "echo-request" (ping)
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}},
					// Apply the rate limit
					&expr.Limit{
						Rate:  rate,
						Burst: burst,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
			logger.Info("firewall", "Enabled ICMP flood protection", "rate", n.config.Security.ICMPFloodRate)
		}
	}

    // 4. JUMP TO BOGON FILTERING CHAIN
    // Drop traffic from unroutable IPs early.
    if err := n.bogonMgr.AddBOGONRules(inputChain); err != nil {
        return err
    }

    // 5. DROP BLACKLISTED IPs
    // Drop known bad actors before any other checks.
    n.conn.AddRule(&nftables.Rule{
        Table: n.table,
        Chain: inputChain,
        Exprs: []expr.Any{
            &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
            &expr.Lookup{SourceRegister: 1, SetName: "blacklist_ips"},
            &expr.Log{Data: []byte("QFF-DROP-BLACKLIST: ")},
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // 6. ACCEPT WHITELISTED IPs
    // Explicitly allow trusted IPs to bypass further restrictions.
    n.conn.AddRule(&nftables.Rule{
        Table: n.table,
        Chain: inputChain,
        Exprs: []expr.Any{
            &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
            &expr.Lookup{SourceRegister: 1, SetName: "whitelist_ips"},
            &expr.Log{Data: []byte("QFF-ACCEPT-WHITELIST: ")},
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })

    // 7. JUMP TO RATE LIMITING CHAIN
    // Apply general rate limits to remaining new connections.
    if err := n.rateLimiter.AddRateLimitRules(inputChain); err != nil {
        return err
    }

    // 8. ADD CONCURRENT CONNECTION LIMIT
    // Apply connection limits before accepting port-specific traffic.
    if n.config.Security.MaxConcurrentConnsPerIP > 0 {
        n.conn.AddRule(&nftables.Rule{
            Table: n.table,
            Chain: inputChain,
            Exprs: []expr.Any{
                // Match only new TCP connections
                &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, // Protocol
                &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},                                // TCP
                &expr.Ct{Key: expr.CtKeySTATE},
                &expr.Bitwise{
                    SourceRegister: 1,
                    DestRegister:   1,
                    Len:            4,
                    Mask:           []byte{0x01}, // NEW
                    Xor:            []byte{0x00},
                },
                &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x01}},
                // Load the source IP to be used as the key for the limit
                &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
                // Apply the connection limit
                &expr.Connlimit{
                    Count: uint32(n.config.Security.MaxConcurrentConnsPerIP),
                    Flags: 1, // Invert flag
                },
                &expr.Log{Data: []byte("QFF-DROP-CONNLIMIT: ")},
                &expr.Verdict{Kind: expr.VerdictDrop},
            },
        })
        logger.Info("firewall", "Enabled concurrent connection limit per IP", "limit", n.config.Security.MaxConcurrentConnsPerIP)
    }

    // 9. SETUP PORT-SPECIFIC RULES
    // Allow traffic to explicitly opened ports.
    if err := n.setupConfigPortRules(); err != nil {
        return err
    }

    // 10. DEFAULT DROP RULE (Catch-all)
    // This is the last rule. If a packet reaches this point, it hasn't been accepted and should be dropped.
    if n.config.Firewall.DefaultPolicy == "drop" {
        n.conn.AddRule(&nftables.Rule{
            Table: n.table,
            Chain: inputChain,
            Exprs: []expr.Any{
                &expr.Log{Data: []byte("QFF-DROP-INPUT: ")},
                &expr.Verdict{Kind: expr.VerdictDrop},
            },
        })
    }

    return nil
}

func (n *NFTManager) setupDynamicDNSRules() error {
	if !n.config.DNS.EnableDynamicDNS {
		return nil
	}

	inputChain := &nftables.Chain{Name: "input", Table: n.table}

	for _, hostname := range n.config.DNS.Hostnames {
		// The DNS manager will create the set. We just need its name.
		setName := n.dnsManager.GenerateSetName(hostname)

		// Add the hostname to the manager, which starts resolving it.
		if err := n.dnsManager.AddHostname(hostname, "allow"); err != nil {
			logger.Error("firewall", "Failed to add dynamic host", "hostname", hostname, "error", err)
			continue
		}

		// Create the rule that uses the set.
		rule := &nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
				&expr.Lookup{SourceRegister: 1, SetName: setName},
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-DNS-%s: ", hostname))},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
		n.conn.AddRule(rule)
		logger.Info("firewall", "Added dynamic DNS rule", "hostname", hostname, "set", setName)
	}

	return nil
}

// Additional helper methods...
func (n *NFTManager) AddWhitelistIP(ip net.IP) error {
	logger.Info("firewall", "Adding IP to whitelist", "ip", ip.String())
	set := &nftables.Set{Name: "whitelist_ips", Table: n.table}
	n.conn.SetAddElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) RemoveWhitelistIP(ip net.IP) error {
	logger.Info("firewall", "Removing IP from whitelist", "ip", ip.String())
	set := &nftables.Set{Name: "whitelist_ips", Table: n.table}
	n.conn.SetDeleteElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) AddBlacklistIP(ip net.IP) error {
	logger.Info("firewall", "Adding IP to blacklist", "ip", ip.String())
	set := &nftables.Set{Name: "blacklist_ips", Table: n.table}
	n.conn.SetAddElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) RemoveBlacklistIP(ip net.IP) error {
	logger.Info("firewall", "Removing IP from blacklist", "ip", ip.String())
	set := &nftables.Set{Name: "blacklist_ips", Table: n.table}
	n.conn.SetDeleteElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) WhitelistCurrentUser() error {
	var detectedIPs []net.IP

	// Method 1: SSH_CLIENT environment variable
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			if ip := net.ParseIP(parts[0]); ip != nil && !ip.IsLoopback() {
				detectedIPs = append(detectedIPs, ip)
				logger.Info("firewall", "Detected SSH client IP from SSH_CLIENT", "ip", ip.String())
			}
		}
	}

	// Method 2: SSH_CONNECTION environment variable
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		parts := strings.Fields(sshConn)
		if len(parts) >= 4 {
			if ip := net.ParseIP(parts[0]); ip != nil && !ip.IsLoopback() {
				// Check if we already have this IP
				found := false
				for _, existingIP := range detectedIPs {
					if existingIP.Equal(ip) {
						found = true
						break
					}
				}
				if !found {
					detectedIPs = append(detectedIPs, ip)
					logger.Info("firewall", "Detected SSH client IP from SSH_CONNECTION", "ip", ip.String())
				}
			}
		}
	}

	// Method 3: Parse /proc/net/tcp for established SSH connections
	if len(detectedIPs) == 0 {
		if sshIPs := n.getSSHConnections(); len(sshIPs) > 0 {
			detectedIPs = append(detectedIPs, sshIPs...)
			logger.Info("firewall", "Detected SSH connections from /proc/net/tcp", "count", len(sshIPs))
		}
	}

	// Method 4: Parse 'who' command output for SSH sessions
	if len(detectedIPs) == 0 {
		if whoIPs := n.getWhoSSHConnections(); len(whoIPs) > 0 {
			detectedIPs = append(detectedIPs, whoIPs...)
			logger.Info("firewall", "Detected SSH connections from 'who' command", "count", len(whoIPs))
		}
	}

	// Whitelist all detected IPs
	if len(detectedIPs) > 0 {
		for _, ip := range detectedIPs {
			if err := n.AddWhitelistIP(ip); err != nil {
				logger.Error("firewall", "Failed to whitelist detected IP", "ip", ip.String(), "error", err.Error())
			} else {
				logger.Info("firewall", "Auto-whitelisted SSH client IP", "ip", ip.String())
			}
		}
		return nil
	}

	logger.Info("firewall", "No remote SSH connections detected, skipping auto-whitelist")
	return nil
}

func (n *NFTManager) setupDockerRules() error {
	if !n.config.Docker.Enabled {
		return nil
	}
	logger.Info("firewall", "Setting up Docker integration rules")

	dockerIfaces, err := n.getDockerInterfaces()
	if err != nil {
		return fmt.Errorf("could not get Docker interfaces: %w", err)
	}
	if len(dockerIfaces) == 0 {
		logger.Info("firewall", "Docker enabled in config, but no Docker interfaces found. Skipping rule creation.")
		return nil
	}

	forwardChain := &nftables.Chain{Name: "forward", Table: n.table}
	inputChain := &nftables.Chain{Name: "input", Table: n.table}

	// Create a set to hold Docker's subnets for easy management
	dockerNetSet := &nftables.Set{
		Name:     "docker_nets",
		Table:    n.table,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := n.conn.AddSet(dockerNetSet, nil); err != nil {
		return fmt.Errorf("failed to create docker_nets set: %w", err)
	}

	// Populate the set from the config file
	var elements []nftables.SetElement
	for _, networkStr := range n.config.Docker.Networks {
		_, network, err := net.ParseCIDR(networkStr)
		if err != nil {
			logger.Warn("firewall", "Invalid CIDR in docker_net config", "network", networkStr)
			continue
		}
		elements = append(elements, nftables.SetElement{
			Key:    network.IP,
			KeyEnd: getNetworkEnd(network),
		})
	}
	if len(elements) > 0 {
		if err := n.conn.SetAddElements(dockerNetSet, elements); err != nil {
			return fmt.Errorf("failed to add elements to docker_nets set: %w", err)
		}
	}

	// Allow traffic from Docker containers to the host machine
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: dockerNetSet.Name},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow established and related traffic to be forwarded
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: []byte{0x02 | 0x04}, // ESTABLISHED | RELATED
				Xor:  []byte{0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow traffic to be forwarded from any Docker interface.
	// This allows container-to-container and container-to-internet traffic.
	for _, iface := range dockerIfaces {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: forwardChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, // Input interface
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface + "\x00")},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	logger.Info("firewall", "Successfully added Docker networking rules", "interfaces", dockerIfaces)
	return nil
}

func getNetworkEnd(network *net.IPNet) net.IP {
	end := make(net.IP, len(network.IP))
	copy(end, network.IP)
	for i := range end {
		end[i] |= ^network.Mask[i]
	}
	return end
}

// parseRateLimit converts a string like "5" into a rate and burst for expr.Limit.
func parseRateLimit(rateStr string) (rate uint64, burst uint32, err error) {
	rateVal, err := strconv.ParseUint(strings.TrimSpace(rateStr), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid rate value: %w", err)
	}

	// Set a sensible default burst value (e.g., the same as the rate, but at least 5)
	burstVal := uint32(rateVal)
	if burstVal < 5 {
		burstVal = 5
	}

	return rateVal, burstVal, nil
}

func (n *NFTManager) setupConfigPortRules() error {
	inputChain := &nftables.Chain{Name: "input", Table: n.table}
	outputChain := &nftables.Chain{Name: "output", Table: n.table}

	// Helper function to create a single rule for a given port
	createRuleForPort := func(port int, protocol string) {
		var protocolNum byte
		protocolStr := "tcp"
		if protocol == "udp" {
			protocolNum = 17
			protocolStr = "udp"
		} else {
			protocolNum = 6
		}

		// Start building the expressions for the rule
		ruleExprs := []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNum}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
		}

		// Check for a specific rate limit for this port
		limitKey := fmt.Sprintf("%s_%d", protocolStr, port)
		if rateStr, hasLimit := n.config.PortRateLimit[limitKey]; hasLimit {
			rate, burst, err := parseRateLimit(rateStr)
			if err != nil {
				logger.Warn("firewall", "Invalid per-port rate limit config, skipping", "key", limitKey, "value", rateStr, "error", err)
			} else {
				// Add the Limit expression. It will only match if the rate is NOT exceeded.
				ruleExprs = append(ruleExprs, &expr.Limit{
					Rate:  rate,
					Burst: burst,
				})
				logger.Info("firewall", "Added per-port rate limit", "port", port, "protocol", protocolStr, "limit", fmt.Sprintf("%d/second", rate))
			}
		}

		// Add the final accept verdict and logging
		ruleExprs = append(ruleExprs, &expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-INPUT-%d: ", port))})
		ruleExprs = append(ruleExprs, &expr.Verdict{Kind: expr.VerdictAccept})

		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: ruleExprs,
		})
		logger.Info("firewall", fmt.Sprintf("Added %s input rule from config", strings.ToUpper(protocolStr)), "port", port)
	}

	// Create rules for all configured inbound ports
	for _, port := range n.config.Ports.TCPIn {
		createRuleForPort(port, "tcp")
	}
	for _, port := range n.config.Ports.UDPIn {
		createRuleForPort(port, "udp")
	}

	// Setup outgoing port rules (no changes needed here)
	for _, port := range n.config.Ports.TCPOut {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table, Chain: outputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
	for _, port := range n.config.Ports.UDPOut {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table, Chain: outputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	return nil
}

// getSSHConnections parses /proc/net/tcp for SSH connections (port 22)
func (n *NFTManager) getSSHConnections() []net.IP {
	var ips []net.IP

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ips
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address (format: IP:PORT in hex)
		localAddr := fields[1]
		if strings.HasSuffix(localAddr, ":0016") { // 0016 = port 22 in hex
			// Parse remote address
			remoteAddr := fields[2]
			if remoteIP := n.parseHexIP(remoteAddr); remoteIP != nil && !remoteIP.IsLoopback() {
				// Check if connection is established (state 01)
				state := fields[3]
				if state == "01" {
					ips = append(ips, remoteIP)
				}
			}
		}
	}

	return ips
}

// getWhoSSHConnections uses the 'who' command to find SSH sessions
func (n *NFTManager) getWhoSSHConnections() []net.IP {
	var ips []net.IP

	cmd := exec.Command("who")
	output, err := cmd.Output()
	if err != nil {
		return ips
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "pts/") && strings.Contains(line, "(") {
			// Extract IP from parentheses: user pts/0 2025-08-16 12:00 (192.168.1.100)
			start := strings.LastIndex(line, "(")
			end := strings.LastIndex(line, ")")
			if start != -1 && end != -1 && end > start {
				ipStr := line[start+1 : end]
				if ip := net.ParseIP(ipStr); ip != nil && !ip.IsLoopback() {
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips
}

// parseHexIP converts hex format IP:PORT to net.IP
func (n *NFTManager) parseHexIP(hexAddr string) net.IP {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return nil
	}

	hexIP := parts[0]
	if len(hexIP) != 8 {
		return nil
	}

	// Convert hex to IP bytes (little endian)
	var ipBytes [4]byte
	for i := 0; i < 4; i++ {
		byteVal, err := strconv.ParseUint(hexIP[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return nil
		}
		ipBytes[3-i] = byte(byteVal) // Reverse byte order
	}

	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
}

func (n *NFTManager) Reload() error {
	logger.Info("firewall", "Reloading nftables configuration")
	n.conn.FlushTable(n.table)

	// Clear tracked rules on reload
	n.rulesMutex.Lock()
	n.trackedRules = make(map[RuleKey]*RuleTracker)
	n.blocklistRules = make(map[string]*nftables.Rule)
	n.rulesMutex.Unlock()

	return n.Initialize()
}

func (n *NFTManager) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	stats["table_name"] = n.table.Name
	stats["dns_hosts"] = len(n.dnsManager.GetHostnames())
	stats["rule_stats"] = n.GetRuleStats()
	return stats, nil
}

// Include other methods like DNS, blocklist management etc...
func (n *NFTManager) AddDynamicHost(hostname string) error {
	return n.dnsManager.AddHostname(hostname, "allow")
}

func (n *NFTManager) GetDynamicHosts() map[string]interface{} {
	hosts := n.dnsManager.GetHostnames()
	result := make(map[string]interface{})
	for k, v := range hosts {
		result[k] = map[string]interface{}{
			"ips":        v.IPs,
			"set_name":   v.SetName,
			"last_check": v.LastCheck,
		}
	}
	return result
}

func (n *NFTManager) RemoveBlocklistSet(setName string) error {
	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	// Remove the rule if it exists
	if rule, exists := n.blocklistRules[setName]; exists {
		n.conn.DelRule(rule)
		delete(n.blocklistRules, setName)
	}

	// Remove the set
	set := &nftables.Set{Name: setName, Table: n.table}
	n.conn.DelSet(set)

	logger.Info("firewall", "Removing blocklist set and rule", "set", setName)
	return n.conn.Flush()
}

func (n *NFTManager) AddBlocklistSet(setName string, ips []net.IP) error {
	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	// 1. Create the set
	set := &nftables.Set{
		Name:    setName,
		Table:   n.table,
		KeyType: nftables.TypeIPAddr,
	}
	if err := n.conn.AddSet(set, nil); err != nil {
		return fmt.Errorf("failed to create blocklist set %s: %w", setName, err)
	}

	// 2. Add elements to the set
	if len(ips) > 0 {
		elements := make([]nftables.SetElement, len(ips))
		for i, ip := range ips {
			elements[i] = nftables.SetElement{Key: ip.To4()}
		}
		if err := n.conn.SetAddElements(set, elements); err != nil {
			return fmt.Errorf("failed to add elements to blocklist set %s: %w", setName, err)
		}
	}

	// 3. Create and add the rule to the input chain
	inputChain := &nftables.Chain{Name: "input", Table: n.table}
	rule := &nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // saddr
			&expr.Lookup{SourceRegister: 1, SetName: setName},
			&expr.Log{Data: []byte(fmt.Sprintf("QFF-DROP-BLOCKLIST-%s: ", setName))},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}
	n.conn.AddRule(rule)

	// 4. Track the rule for later removal
	n.blocklistRules[setName] = rule

	logger.Info("firewall", "Adding blocklist set and rule", "set", setName, "count", len(ips))
	return n.conn.Flush()
}

func (n *NFTManager) BackupCurrentState() (*FirewallState, error) {
	// Use the 'nft' command to list the current ruleset
	cmd := exec.Command("nft", "list", "ruleset")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute 'nft list ruleset': %w", err)
	}

	logger.Info("firewall", "Successfully backed up current firewall state")
	return &FirewallState{Ruleset: out.Bytes()}, nil
}

func (n *NFTManager) RestoreState(state *FirewallState) error {
	if state == nil || len(state.Ruleset) == 0 {
		return fmt.Errorf("invalid or empty state provided for restore")
	}

	// Use the 'nft' command to restore the ruleset from the backup
	cmd := exec.Command("nft", "-f", "-") // '-f -' reads from stdin
	cmd.Stdin = bytes.NewReader(state.Ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute 'nft -f -' to restore ruleset: %w\nError output: %s", err, stderr.String())
	}

	logger.Info("firewall", "Successfully restored firewall state from backup")
	return nil
}

// FlushRuleset executes 'nft flush ruleset' to clear all rules.
func (n *NFTManager) FlushRuleset() error {
	logger.Info("firewall", "Flushing all nftables ruleset")
	cmd := exec.Command("nft", "flush", "ruleset")
	if err := cmd.Run(); err != nil {
		// Log the error from the command for better debugging
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		return fmt.Errorf("failed to execute 'nft flush ruleset': %w, stderr: %s", err, stderr.String())
	}
	return nil
}