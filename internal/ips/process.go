// internal/ips/process.go
package ips

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
)

type ProcessMonitor struct {
	config          *config.IPSConfig
	ipsManager      *IPSManager
	suspiciousProcs map[int]*SuspiciousProcess
	patterns        []*regexp.Regexp
	mu              sync.RWMutex
	stopCh          chan struct{}
}

type SuspiciousProcess struct {
	PID       int
	Name      string
	Command   string
	User      string
	MemoryMB  int
	StartTime time.Time
	LastSeen  time.Time
	Reason    string
}

func NewProcessMonitor(cfg *config.IPSConfig, ipsManager *IPSManager) *ProcessMonitor {
	pm := &ProcessMonitor{
		config:          cfg,
		ipsManager:      ipsManager,
		suspiciousProcs: make(map[int]*SuspiciousProcess),
		stopCh:          make(chan struct{}),
	}

	pm.initializePatterns()
	return pm
}

func (p *ProcessMonitor) initializePatterns() {
	// Set default suspicious patterns if not configured
	if len(p.config.SuspiciousProcesses) == 0 {
		p.config.SuspiciousProcesses = []string{
			`perl /tmp/.*\.pl`,
			`php.*mailer`,
			`wget http.*\.php`,
			`curl.*\.sh`,
			`python.*backdoor`,
			`nc -l.*`,
			`/tmp/.*\.py`,
			`bash.*reverse`,
			`sh.*shell`,
			`.*\.php.*system`,
		}
	}

	if p.config.MaxProcessMemory == "" {
		p.config.MaxProcessMemory = "1GB"
	}

	if p.config.ProcessCheckInterval == 0 {
		p.config.ProcessCheckInterval = 1 * time.Minute
	}

	// Compile regex patterns
	for _, pattern := range p.config.SuspiciousProcesses {
		if regex, err := regexp.Compile(pattern); err == nil {
			p.patterns = append(p.patterns, regex)
		}
	}
}

func (p *ProcessMonitor) Start() error {
	if !p.config.EnableProcessMonitor {
		return nil
	}

	logger.Info("process", "Starting process monitor")

	go p.startMonitoring()
	go p.cleanupOldProcesses()

	return nil
}

func (p *ProcessMonitor) startMonitoring() {
	ticker := time.NewTicker(p.config.ProcessCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.scanProcesses()
		case <-p.stopCh:
			return
		}
	}
}

func (p *ProcessMonitor) scanProcesses() {
	processes, err := p.getProcessList()
	if err != nil {
		logger.Error("process", "Failed to get process list", "error", err.Error())
		return
	}

	for _, proc := range processes {
		p.analyzeProcess(proc)
	}
}

func (p *ProcessMonitor) getProcessList() ([]*ProcessInfo, error) {
	var processes []*ProcessInfo

	// Read /proc/*/stat for process information
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			if proc := p.readProcessInfo(pid); proc != nil {
				processes = append(processes, proc)
			}
		}
	}

	return processes, nil
}

type ProcessInfo struct {
	PID      int
	Name     string
	Command  string
	User     string
	MemoryKB int
}

func (p *ProcessMonitor) readProcessInfo(pid int) *ProcessInfo {
	// Read /proc/PID/stat
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statFile, err := os.Open(statPath)
	if err != nil {
		return nil
	}
	defer statFile.Close()

	scanner := bufio.NewScanner(statFile)
	if !scanner.Scan() {
		return nil
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 24 {
		return nil
	}

	name := strings.Trim(fields[1], "()")

	// Read command line
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdline := p.readCmdline(cmdlinePath)

	// Read memory usage from /proc/PID/status
	memoryKB := p.readMemoryUsage(pid)

	// Read user from /proc/PID/status
	user := p.readProcessUser(pid)

	return &ProcessInfo{
		PID:      pid,
		Name:     name,
		Command:  cmdline,
		User:     user,
		MemoryKB: memoryKB,
	}
}

func (p *ProcessMonitor) readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	// Replace null bytes with spaces
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline)
}

func (p *ProcessMonitor) readMemoryUsage(pid int) int {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil {
					return kb
				}
			}
		}
	}
	return 0
}

func (p *ProcessMonitor) readProcessUser(pid int) string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1] // Real UID
			}
		}
	}
	return ""
}

func (p *ProcessMonitor) analyzeProcess(proc *ProcessInfo) {
	reasons := []string{}

	// Check against suspicious patterns
	for _, pattern := range p.patterns {
		if pattern.MatchString(proc.Command) || pattern.MatchString(proc.Name) {
			reasons = append(reasons, fmt.Sprintf("Matches pattern: %s", pattern.String()))
		}
	}

	// Check memory usage
	maxMemoryMB := p.parseMemoryLimit(p.config.MaxProcessMemory)
	if proc.MemoryKB/1024 > maxMemoryMB {
		reasons = append(reasons, fmt.Sprintf("High memory usage: %dMB", proc.MemoryKB/1024))
	}

	// Check for suspicious locations
	if strings.Contains(proc.Command, "/tmp/") || strings.Contains(proc.Command, "/var/tmp/") {
		reasons = append(reasons, "Running from temporary directory")
	}

	// Check for suspicious users (processes running as www-data, nobody that shouldn't)
	if proc.User == "33" || proc.User == "65534" { // www-data, nobody
		if strings.Contains(proc.Command, "wget") || strings.Contains(proc.Command, "curl") {
			reasons = append(reasons, "Web user running download tools")
		}
	}

	if len(reasons) > 0 {
		p.handleSuspiciousProcess(proc, reasons)
	}
}

func (p *ProcessMonitor) parseMemoryLimit(limit string) int {
	limit = strings.ToUpper(limit)

	var multiplier int = 1
	if strings.HasSuffix(limit, "GB") {
		multiplier = 1024
		limit = strings.TrimSuffix(limit, "GB")
	} else if strings.HasSuffix(limit, "MB") {
		multiplier = 1
		limit = strings.TrimSuffix(limit, "MB")
	}

	if value, err := strconv.Atoi(limit); err == nil {
		return value * multiplier
	}

	return 1024 // Default 1GB
}

func (p *ProcessMonitor) handleSuspiciousProcess(proc *ProcessInfo, reasons []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	suspProc := &SuspiciousProcess{
		PID:       proc.PID,
		Name:      proc.Name,
		Command:   proc.Command,
		User:      proc.User,
		MemoryMB:  proc.MemoryKB / 1024,
		StartTime: time.Now(),
		LastSeen:  time.Now(),
		Reason:    strings.Join(reasons, "; "),
	}

	p.suspiciousProcs[proc.PID] = suspProc

	logger.Warn("process", "Suspicious process detected",
		"pid", proc.PID,
		"name", proc.Name,
		"command", proc.Command,
		"reasons", suspProc.Reason)

	// Send alert
	data := map[string]interface{}{
		"pid":       proc.PID,
		"name":      proc.Name,
		"command":   proc.Command,
		"user":      proc.User,
		"memory_mb": proc.MemoryKB / 1024,
		"reasons":   reasons,
	}

	message := fmt.Sprintf("SECURITY: Suspicious process detected: %s (PID %d)", proc.Name, proc.PID)
	p.ipsManager.notifier.SendAlert(message, data)

	// Optionally kill the process (careful with this!)
	// if you want to auto-kill suspicious processes:
	// p.killProcess(proc.PID)
}

func (p *ProcessMonitor) killProcess(pid int) {
	logger.Warn("process", "Killing suspicious process", "pid", pid)

	// Send SIGTERM first
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		logger.Error("process", "Failed to terminate process", "pid", pid, "error", err.Error())

		// If SIGTERM fails, try SIGKILL
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			logger.Error("process", "Failed to kill process", "pid", pid, "error", err.Error())
		}
	}
}

func (p *ProcessMonitor) cleanupOldProcesses() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for pid, proc := range p.suspiciousProcs {
				// Remove entries older than 1 hour or if process no longer exists
				if now.Sub(proc.LastSeen) > 1*time.Hour || !p.processExists(pid) {
					delete(p.suspiciousProcs, pid)
				}
			}
			p.mu.Unlock()
		case <-p.stopCh:
			return
		}
	}
}

func (p *ProcessMonitor) processExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func (p *ProcessMonitor) Stop() {
	close(p.stopCh)
}

func (p *ProcessMonitor) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"suspicious_processes": len(p.suspiciousProcs),
		"enabled":              p.config.EnableProcessMonitor,
		"patterns_loaded":      len(p.patterns),
	}
}

func (p *ProcessMonitor) GetSuspiciousProcesses() map[int]*SuspiciousProcess {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[int]*SuspiciousProcess)
	for k, v := range p.suspiciousProcs {
		result[k] = v
	}
	return result
}
