// internal/ips/ips.go
package ips

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/firewall"
	"qff/internal/geoip"
	"qff/internal/logger"
	"qff/internal/notify"
)

type IPSManager struct {
	config            *config.Config // Use the main config
	firewall          *firewall.NFTManager
	notifier          *notify.Notifier
	geoipManager      *geoip.EnhancedGeoIPManager
	blockedIPs        map[string]*BlockEntry
	tempWhitelist     map[string]*WhitelistEntry
	tempBlocklist     map[string]*BlockEntry
	attackCounters    map[string]*AttackCounter
	mu                sync.RWMutex
	stopCh            chan struct{}
	logPatterns       map[string]*DetectionRule
	portScanDetector  *PortScanDetector
	fileSystemMonitor *FileSystemMonitor
	processMonitor    *ProcessMonitor
	blocklistManager  *ExternalBlocklistManager
}

type BlockEntry struct {
	IP         net.IP
	Reason     string
	BlockTime  time.Time
	ExpiryTime *time.Time
	Permanent  bool
	HitCount   int
	LastSeen   time.Time
}

type WhitelistEntry struct {
	IP         net.IP
	ExpiryTime *time.Time
	Permanent  bool
	Reason     string
	AddedTime  time.Time
}

type AttackCounter struct {
	IP         net.IP
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	LogEntries []string
}

type DetectionRule struct {
	Name       string
	Pattern    *regexp.Regexp
	Threshold  int
	TimeWindow time.Duration
	LogFiles   []string
}

func NewIPSManager(cfg *config.Config, fw *firewall.NFTManager, notifier *notify.Notifier, geoipMgr *geoip.EnhancedGeoIPManager) *IPSManager {
	ips := &IPSManager{
		config:         cfg,
		firewall:       fw,
		notifier:       notifier,
		geoipManager:   geoipMgr,
		blockedIPs:     make(map[string]*BlockEntry),
		tempWhitelist:  make(map[string]*WhitelistEntry),
		tempBlocklist:  make(map[string]*BlockEntry),
		attackCounters: make(map[string]*AttackCounter),
		stopCh:         make(chan struct{}),
		logPatterns:    make(map[string]*DetectionRule),
	}

	ips.portScanDetector = NewPortScanDetector(&cfg.IPS, ips)
	ips.fileSystemMonitor = NewFileSystemMonitor(&cfg.IPS, ips)
	ips.processMonitor = NewProcessMonitor(&cfg.IPS, ips)
	ips.blocklistManager = NewExternalBlocklistManager(&cfg.IPS, ips)

	ips.initializePatterns()
	return ips
}

// AddTempBlock adds a manual temporary block for an IP.
func (i *IPSManager) AddTempBlock(ip net.IP, duration time.Duration, reason string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	if _, exists := i.blockedIPs[key]; exists {
		return fmt.Errorf("IP %s is already blocked", ip.String())
	}

	expiryTime := time.Now().Add(duration)
	entry := &BlockEntry{
		IP:         ip,
		Reason:     reason,
		BlockTime:  time.Now(),
		ExpiryTime: &expiryTime,
		Permanent:  false,
	}

	i.blockedIPs[key] = entry
	i.tempBlocklist[key] = entry // Also track it as a manual temp block

	if err := i.firewall.AddBlacklistIP(ip); err != nil {
		// Rollback if firewall rule fails
		delete(i.blockedIPs, key)
		delete(i.tempBlocklist, key)
		return err
	}

	logger.Info("ips", "Temporarily blocked IP", "ip", ip.String(), "duration", duration, "reason", reason)
	return nil
}

// RemoveTempRule removes a temporary rule (either allow or deny).
func (i *IPSManager) RemoveTempRule(ip net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()

	// Check temp whitelist first
	if _, exists := i.tempWhitelist[key]; exists {
		delete(i.tempWhitelist, key)
		i.firewall.RemoveWhitelistIP(ip)
		logger.Info("ips", "Removed temporary whitelist for IP", "ip", ip.String())
		return nil
	}

	// Check temp blocklist
	if _, exists := i.tempBlocklist[key]; exists {
		delete(i.tempBlocklist, key)
		delete(i.blockedIPs, key) // Also remove from main block list
		i.firewall.RemoveBlacklistIP(ip)
		logger.Info("ips", "Removed temporary block for IP", "ip", ip.String())
		return nil
	}

	return fmt.Errorf("no temporary rule found for IP %s", ip.String())
}

// ... (the rest of the file remains the same)
func (i *IPSManager) initializePatterns() {
	// Use shortcuts to the correct config sections
	rules := i.config.DetectionRules
	ipsCfg := i.config.IPS

	i.logPatterns["apache_scan"] = &DetectionRule{
		Name:       "Apache 404 Scanning",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP/1\.[01]" 404`),
		Threshold:  rules.ApacheScanThreshold,
		TimeWindow: 2 * time.Minute,
		LogFiles:   ipsCfg.ApacheLogFiles,
	}

	// DirectAdmin login failures
	i.logPatterns["directadmin_failed"] = &DetectionRule{
		Name:       "DirectAdmin Failed Login",
		Pattern:    regexp.MustCompile(`SECURITY_VIOLATION\|([0-9.]+)\|.*\|LOGIN_FAILED`),
		Threshold:  rules.DirectAdminFailedLogins,
		TimeWindow: ipsCfg.DirectAdminTimeWindow,
		LogFiles:   ipsCfg.DirectAdminLogFiles,
	}

	// WordPress login failures
	i.logPatterns["wordpress_failed"] = &DetectionRule{
		Name:       "WordPress Failed Login",
		Pattern:    regexp.MustCompile(`authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)`),
		Threshold:  rules.WordPressFailedLogins,
		TimeWindow: ipsCfg.WordPressTimeWindow,
		LogFiles:   ipsCfg.AuthLogFiles,
	}

	// Nginx scanning
	i.logPatterns["nginx_scan"] = &DetectionRule{
		Name:       "Nginx 404 Scanning",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP/1\.[01]" 404`),
		Threshold:  rules.NginxScanThreshold,
		TimeWindow: 2 * time.Minute,
		LogFiles:   ipsCfg.NginxLogFiles,
	}

	// FTP brute force
	i.logPatterns["ftp_failed"] = &DetectionRule{
		Name:       "FTP Failed Login",
		Pattern:    regexp.MustCompile(`FAIL LOGIN.*Client "(\d+\.\d+\.\d+\.\d+)"`),
		Threshold:  rules.FTPFailedThreshold,
		TimeWindow: 5 * time.Minute,
		LogFiles:   ipsCfg.FTPLogFiles,
	}

	// SMTP Authentication failures
	i.logPatterns["smtp_auth_failed"] = &DetectionRule{
		Name:       "SMTP Auth Failed",
		Pattern:    regexp.MustCompile(`warning: [^[]*\[(\d+\.\d+\.\d+\.\d+)\]: SASL.*authentication failed`),
		Threshold:  rules.SMTPAuthFailedThreshold,
		TimeWindow: 15 * time.Minute,
		LogFiles:   ipsCfg.MailLogFiles,
	}

	// SQL Injection (Apache)
	i.logPatterns["apache_sql_injection"] = &DetectionRule{
		Name:       "SQL Injection Attempt",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"[^"]*(?:union|select|insert|delete|update|drop|create|alter).*(?:from|where|join).*"`),
		Threshold:  rules.SQLInjectionThreshold,
		TimeWindow: 1 * time.Minute,
		LogFiles:   ipsCfg.ApacheLogFiles,
	}

	// SQL Injection (Nginx)
	i.logPatterns["nginx_sql_injection"] = &DetectionRule{
		Name:       "SQL Injection Attempt",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"[^"]*(?:union|select|insert|delete|update|drop|create|alter).*(?:from|where|join).*"`),
		Threshold:  rules.SQLInjectionThreshold,
		TimeWindow: 1 * time.Minute,
		LogFiles:   ipsCfg.NginxLogFiles,
	}

	// Shell Upload (Apache)
	i.logPatterns["apache_shell_upload"] = &DetectionRule{
		Name:       "Shell Upload Attempt",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"POST.*\.(?:php|asp|jsp|sh).*"`),
		Threshold:  rules.ShellUploadThreshold,
		TimeWindow: 1 * time.Minute,
		LogFiles:   ipsCfg.ApacheLogFiles,
	}

	// Shell Upload (Nginx)
	i.logPatterns["nginx_shell_upload"] = &DetectionRule{
		Name:       "Shell Upload Attempt",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"POST.*\.(?:php|asp|jsp|sh).*"`),
		Threshold:  rules.ShellUploadThreshold,
		TimeWindow: 1 * time.Minute,
		LogFiles:   ipsCfg.NginxLogFiles,
	}
}


func (i *IPSManager) Start() error {
	if !i.config.IPS.EnableIPS {
		return nil
	}

	logger.Info("ips", "Starting IPS manager")

	if i.config.IPS.AutoWhitelistSSH {
		i.autoWhitelistSSHSessions()
	}

	// Auto-whitelist current SSH session
	if i.config.IPS.AutoWhitelistSSH {
		i.autoWhitelistSSHSessions()
	}

	// Start Phase 1 components
	go i.startLogMonitoring()
	go i.startCleanupRoutine()

	// Start Phase 2 components
	if err := i.portScanDetector.Start(); err != nil {
		logger.Error("ips", "Failed to start port scan detector", "error", err.Error())
	}

	if err := i.fileSystemMonitor.Start(); err != nil {
		logger.Error("ips", "Failed to start filesystem monitor", "error", err.Error())
	}

	if err := i.processMonitor.Start(); err != nil {
		logger.Error("ips", "Failed to start process monitor", "error", err.Error())
	}

	if err := i.blocklistManager.Start(); err != nil {
		logger.Error("ips", "Failed to start blocklist manager", "error", err.Error())
	}

	return nil
}

func (i *IPSManager) setDefaultLogFiles() {
	if len(i.config.IPS.CPanelLogFiles) == 0 {
		i.config.IPS.CPanelLogFiles = []string{"/usr/local/cpanel/logs/login_log", "/usr/local/cpanel/logs/access_log"}
	}

	if len(i.config.IPS.DirectAdminLogFiles) == 0 {
		i.config.IPS.DirectAdminLogFiles = []string{"/var/log/directadmin/security.log", "/var/log/directadmin/login.log"}
	}

	if len(i.config.IPS.ApacheLogFiles) == 0 {
		i.config.IPS.ApacheLogFiles = []string{"/var/log/apache2/access.log", "/var/log/httpd/access_log"}
	}

	if len(i.config.IPS.NginxLogFiles) == 0 {
		i.config.IPS.NginxLogFiles = []string{"/var/log/nginx/access.log"}
	}

	if len(i.config.IPS.MailLogFiles) == 0 {
		i.config.IPS.MailLogFiles = []string{"/var/log/mail.log", "/var/log/maillog"}
	}

	if len(i.config.IPS.FTPLogFiles) == 0 {
		i.config.IPS.FTPLogFiles = []string{"/var/log/vsftpd.log", "/var/log/proftpd/proftpd.log"}
	}

	if len(i.config.IPS.AuthLogFiles) == 0 {
		i.config.IPS.AuthLogFiles = []string{"/var/log/auth.log", "/var/log/secure"}
	}
}

func (i *IPSManager) autoWhitelistSSHSessions() {
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			ip := net.ParseIP(parts[0])
			// --- CHANGE is here ---
			if ip != nil && !ip.IsLoopback() {
				expiryTime := time.Now().Add(i.config.IPS.SSHWhitelistDuration)
				i.addTempWhitelist(ip, &expiryTime, "Auto SSH session")
				logger.Info("ips", "Auto-whitelisted SSH session", "ip", ip.String(), "expires", expiryTime)
			}
		}
	}
}

func (i *IPSManager) addTempWhitelist(ip net.IP, expiryTime *time.Time, reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	i.tempWhitelist[key] = &WhitelistEntry{
		IP:         ip,
		ExpiryTime: expiryTime,
		Permanent:  expiryTime == nil,
		Reason:     reason,
		AddedTime:  time.Now(),
	}

	// Add to firewall whitelist
	i.firewall.AddWhitelistIP(ip)
}

func (i *IPSManager) startLogMonitoring() {
	// --- CHANGE is here ---
	ticker := time.NewTicker(i.config.IPS.LogCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.processLogs()
		case <-i.stopCh:
			return
		}
	}
}

func (i *IPSManager) processLogs() {
	for _, rule := range i.logPatterns {
		for _, logFile := range rule.LogFiles {
			i.processLogFile(rule, logFile)
		}
	}
}

func (i *IPSManager) processLogFile(rule *DetectionRule, logFile string) {
	file, err := os.Open(logFile)
	if err != nil {
		// Log file doesn't exist, skip silently
		return
	}
	defer file.Close()

	// Read last N lines (simple implementation - can be optimized)
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Process recent entries (last 100 lines)
	start := len(lines) - 100
	if start < 0 {
		start = 0
	}

	for _, line := range lines[start:] {
		i.processLogLine(line, rule)
	}
}

func (i *IPSManager) processLogLine(line string, rule *DetectionRule) {
	matches := rule.Pattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return
	}

	ipStr := matches[1]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// Check if IP is whitelisted
	if i.isWhitelisted(ip) {
		return
	}

	// Track attack
	i.trackAttack(ip, line)

	// Check if threshold exceeded
	if i.shouldBlock(ip, rule) {
		i.blockIP(ip, rule.Name, false)
	}
}

func (i *IPSManager) isWhitelisted(ip net.IP) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	key := ip.String()
	entry, exists := i.tempWhitelist[key]
	if !exists {
		return false
	}

	// Check if temporary whitelist expired
	if entry.ExpiryTime != nil && time.Now().After(*entry.ExpiryTime) {
		delete(i.tempWhitelist, key)
		i.firewall.RemoveWhitelistIP(ip)
		return false
	}

	return true
}

func (i *IPSManager) trackAttack(ip net.IP, logEntry string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	counter, exists := i.attackCounters[key]

	if !exists {
		counter = &AttackCounter{
			IP:         ip,
			Count:      0,
			FirstSeen:  time.Now(),
			LogEntries: []string{},
		}
		i.attackCounters[key] = counter
	}

	counter.Count++
	counter.LastSeen = time.Now()
	counter.LogEntries = append(counter.LogEntries, logEntry)

	// Keep only last 10 log entries
	if len(counter.LogEntries) > 10 {
		counter.LogEntries = counter.LogEntries[1:]
	}
}

func (i *IPSManager) shouldBlock(ip net.IP, rule *DetectionRule) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	key := ip.String()
	counter, exists := i.attackCounters[key]
	if !exists {
		return false
	}

	// Check if within time window and exceeded threshold
	if time.Since(counter.FirstSeen) <= rule.TimeWindow && counter.Count >= rule.Threshold {
		return true
	}

	return false
}

func (i *IPSManager) blockIP(ip net.IP, reason string, permanent bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()

	if _, exists := i.blockedIPs[key]; exists {
		return
	}

	var expiryTime *time.Time
	if !permanent {
		// --- CHANGE is here ---
		expiry := time.Now().Add(i.config.IPS.TempBlockDuration)
		expiryTime = &expiry
	}

	entry := &BlockEntry{
		IP:         ip,
		Reason:     reason,
		BlockTime:  time.Now(),
		ExpiryTime: expiryTime,
		Permanent:  permanent,
		HitCount:   1,
		LastSeen:   time.Now(),
	}

	i.blockedIPs[key] = entry
	i.firewall.AddBlacklistIP(ip)

	// --- And here ---
	if i.config.IPS.EnableBlockNotifications {
		i.sendBlockNotification(entry)
	}

	logger.Info("ips", "Blocked IP", "ip", ip.String(), "reason", reason, "permanent", permanent)
}

func (i *IPSManager) sendBlockNotification(entry *BlockEntry) {
	// Get attack details
	key := entry.IP.String()
	counter := i.attackCounters[key]

	data := map[string]interface{}{
		"ip":         entry.IP.String(),
		"reason":     entry.Reason,
		"permanent":  entry.Permanent,
		"block_time": entry.BlockTime,
	}

	if counter != nil {
		data["attack_count"] = counter.Count
		data["first_seen"] = counter.FirstSeen
		data["log_sample"] = counter.LogEntries[len(counter.LogEntries)-1]
	}

	message := fmt.Sprintf("IPS: Blocked %s for %s", entry.IP.String(), entry.Reason)
	i.notifier.SendAlert(message, data)
}

func (i *IPSManager) startCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.cleanupExpiredEntries()
		case <-i.stopCh:
			return
		}
	}
}

func (i *IPSManager) cleanupExpiredEntries() {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()

	// Cleanup expired blocks
	for key, entry := range i.blockedIPs {
		if entry.ExpiryTime != nil && now.After(*entry.ExpiryTime) {
			i.firewall.RemoveBlacklistIP(entry.IP)
			delete(i.blockedIPs, key)
			// Also remove from tempBlocklist if it was a manual temp block
			delete(i.tempBlocklist, key)
			logger.Info("ips", "Unblocked expired IP", "ip", entry.IP.String())
		}
	}

	// Cleanup expired whitelists
	for key, entry := range i.tempWhitelist {
		if entry.ExpiryTime != nil && now.After(*entry.ExpiryTime) {
			i.firewall.RemoveWhitelistIP(entry.IP)
			delete(i.tempWhitelist, key)
			logger.Info("ips", "Removed expired whitelist", "ip", entry.IP.String())
		}
	}

	// Cleanup old attack counters
	for key, counter := range i.attackCounters {
		if now.Sub(counter.LastSeen) > 1*time.Hour {
			delete(i.attackCounters, key)
		}
	}
}

func (i *IPSManager) GetBlockedIPs() map[string]*BlockEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make(map[string]*BlockEntry)
	for k, v := range i.blockedIPs {
		result[k] = v
	}
	return result
}

func (i *IPSManager) Stop() {
	close(i.stopCh)

	// Stop Phase 2 components
	if i.portScanDetector != nil {
		i.portScanDetector.Stop()
	}
	if i.fileSystemMonitor != nil {
		i.fileSystemMonitor.Stop()
	}
	if i.processMonitor != nil {
		i.processMonitor.Stop()
	}
	if i.blocklistManager != nil {
		i.blocklistManager.Stop()
	}
}

func (i *IPSManager) UnblockIP(ip net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	entry, exists := i.blockedIPs[key]
	if !exists {
		return fmt.Errorf("IP not blocked")
	}

	// Remove from firewall
	if err := i.firewall.RemoveBlacklistIP(ip); err != nil {
		return err
	}

	// Remove from all relevant lists
	delete(i.blockedIPs, key)
	delete(i.tempBlocklist, key)

	logger.Info("ips", "Manually unblocked IP", "ip", ip.String(), "reason", entry.Reason)
	return nil
}

func (i *IPSManager) RemoveWhitelist(ip net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	_, exists := i.tempWhitelist[key]
	if !exists {
		return fmt.Errorf("IP not whitelisted")
	}

	// Remove from whitelist
	delete(i.tempWhitelist, key)
	i.firewall.RemoveWhitelistIP(ip)

	logger.Info("ips", "Removed whitelist", "ip", ip.String())
	return nil
}

func (i *IPSManager) GetWhitelistedIPs() map[string]*WhitelistEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make(map[string]*WhitelistEntry)
	for k, v := range i.tempWhitelist {
		result[k] = v
	}
	return result
}

func (i *IPSManager) AddWhitelist(ip net.IP, permanent bool, reason string) error {
	var expiryTime *time.Time
	if !permanent {
		// --- CHANGE is here ---
		expiry := time.Now().Add(i.config.IPS.SSHWhitelistDuration)
		expiryTime = &expiry
	}

	i.addTempWhitelist(ip, expiryTime, reason)
	logger.Info("ips", "Added whitelist", "ip", ip.String(), "permanent", permanent, "reason", reason)
	return nil
}

func (i *IPSManager) GetStats() map[string]interface{} {
	i.mu.RLock()
	defer i.mu.RUnlock()

	stats := map[string]interface{}{
		"blocked_count":     len(i.blockedIPs),
		"whitelisted_count": len(i.tempWhitelist),
		"attack_counters":   len(i.attackCounters),
		"enabled":           i.config.IPS.EnableIPS,
		"patterns_loaded":   len(i.logPatterns),
	}

	// Add Phase 2 stats
	if i.portScanDetector != nil {
		stats["port_scan_detector"] = i.portScanDetector.GetStats()
	}
	if i.fileSystemMonitor != nil {
		stats["filesystem_monitor"] = i.fileSystemMonitor.GetStats()
	}
	if i.processMonitor != nil {
		stats["process_monitor"] = i.processMonitor.GetStats()
	}
	if i.blocklistManager != nil {
		stats["blocklist_manager"] = i.blocklistManager.GetStats()
	}

	// Count by reason
	reasonStats := make(map[string]int)
	for _, entry := range i.blockedIPs {
		reasonStats[entry.Reason]++
	}
	stats["blocked_by_reason"] = reasonStats

	return stats
}
