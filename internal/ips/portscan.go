// internal/ips/portscan.go
package ips

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
)

type PortScanDetector struct {
	config       *config.IPSConfig
	ipsManager   *IPSManager
	scanCounters map[string]*ScanCounter
	mu           sync.RWMutex
	stopCh       chan struct{}
}

type ScanCounter struct {
	IP            net.IP
	PortsScanned  map[int]bool
	FirstSeen     time.Time
	LastSeen      time.Time
	TotalAttempts int
}

func NewPortScanDetector(cfg *config.IPSConfig, ipsManager *IPSManager) *PortScanDetector {
	return &PortScanDetector{
		config:       cfg,
		ipsManager:   ipsManager,
		scanCounters: make(map[string]*ScanCounter),
		stopCh:       make(chan struct{}),
	}
}

func (p *PortScanDetector) Start() error {
	if !p.config.EnablePortScanDetection {
		return nil
	}

	logger.Info("portscan", "Starting port scan detector")

	go p.monitorNetstat()
	go p.monitorKernelLogs()
	go p.cleanupCounters()

	return nil
}

func (p *PortScanDetector) monitorNetstat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.checkConnections()
		case <-p.stopCh:
			return
		}
	}
}

func (p *PortScanDetector) checkConnections() {
	// Parse /proc/net/tcp for connection attempts
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	connectionCounts := make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse remote address
		remoteAddr := fields[2]
		if ipStr := p.parseIPFromHex(remoteAddr); ipStr != "" {
			connectionCounts[ipStr]++
		}
	}

	// Check for suspicious connection patterns
	for ipStr, count := range connectionCounts {
		if count > 20 { // Threshold for suspicious activity
			ip := net.ParseIP(ipStr)
			if ip != nil {
				p.trackScan(ip, 0, "Multiple connection attempts")
			}
		}
	}
}

func (p *PortScanDetector) parseIPFromHex(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return ""
	}

	// Convert hex IP to dotted decimal
	hexIP := parts[0]
	if len(hexIP) != 8 {
		return ""
	}

	var ip []byte
	for i := 0; i < 8; i += 2 {
		b, err := strconv.ParseUint(hexIP[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		ip = append(ip, byte(b))
	}

	// Reverse byte order (little endian)
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

func (p *PortScanDetector) monitorKernelLogs() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.checkKernelLogs()
		case <-p.stopCh:
			return
		}
	}
}

func (p *PortScanDetector) checkKernelLogs() {
	// Monitor dmesg for dropped packets that might indicate scanning
	file, err := os.Open("/var/log/kern.log")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// SYN flood pattern
	synPattern := regexp.MustCompile(`SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*SYN`)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Process last 50 lines
	start := len(lines) - 50
	if start < 0 {
		start = 0
	}

	for _, line := range lines[start:] {
		if matches := synPattern.FindStringSubmatch(line); len(matches) >= 3 {
			ip := net.ParseIP(matches[1])
			if port, err := strconv.Atoi(matches[2]); err == nil && ip != nil {
				p.trackScan(ip, port, "SYN scan detected")
			}
		}
	}
}

func (p *PortScanDetector) trackScan(ip net.IP, port int, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := ip.String()
	counter, exists := p.scanCounters[key]

	if !exists {
		counter = &ScanCounter{
			IP:            ip,
			PortsScanned:  make(map[int]bool),
			FirstSeen:     time.Now(),
			TotalAttempts: 0,
		}
		p.scanCounters[key] = counter
	}

	counter.LastSeen = time.Now()
	counter.TotalAttempts++

	if port > 0 {
		counter.PortsScanned[port] = true
	}

	// Check if threshold exceeded
	if len(counter.PortsScanned) >= p.config.PortScanThreshold ||
		counter.TotalAttempts >= p.config.PortScanThreshold*2 {

		logger.Info("portscan", "Port scan detected", "ip", ip.String(), "ports", len(counter.PortsScanned), "attempts", counter.TotalAttempts)

		// Block the IP
		p.ipsManager.blockIP(ip, "Port scanning", false)
	}
}

func (p *PortScanDetector) cleanupCounters() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for key, counter := range p.scanCounters {
				if now.Sub(counter.LastSeen) > p.config.PortScanTimeWindow {
					delete(p.scanCounters, key)
				}
			}
			p.mu.Unlock()
		case <-p.stopCh:
			return
		}
	}
}

func (p *PortScanDetector) Stop() {
	close(p.stopCh)
}

func (p *PortScanDetector) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"active_scanners": len(p.scanCounters),
		"enabled":         p.config.EnablePortScanDetection,
		"threshold":       p.config.PortScanThreshold,
	}
}
