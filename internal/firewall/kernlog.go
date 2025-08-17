// internal/firewall/kernlog.go
package firewall

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"qff/internal/logger"
)

type KernelLogMonitor struct {
	mu     sync.RWMutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Regex patterns for parsing nftables kernel log messages
var (
	qffLogPattern = regexp.MustCompile(`QFF-(\w+)-(\w+)(?:-(\d+))?: .*IN=(\w*) OUT=(\w*) MAC=([^ ]*) SRC=([^ ]*) DST=([^ ]*) .*PROTO=(\w+)(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?`)
)

func NewKernelLogMonitor() *KernelLogMonitor {
	return &KernelLogMonitor{
		stopCh: make(chan struct{}),
	}
}

func (k *KernelLogMonitor) Start() error {
	logger.Info("kernlog", "Starting kernel log monitor for firewall events")

	k.wg.Add(1)
	go k.monitorKernelLog()

	return nil
}

func (k *KernelLogMonitor) Stop() {
	close(k.stopCh)
	k.wg.Wait()
	logger.Info("kernlog", "Kernel log monitor stopped")
}

func (k *KernelLogMonitor) monitorKernelLog() {
	defer k.wg.Done()

	// Try multiple kernel log sources
	logSources := []string{
		"/proc/kmsg",        // Direct kernel messages
		"/dev/kmsg",         // Alternative kernel messages
		"/var/log/kern.log", // Syslog kernel messages
		"/var/log/messages", // System messages
	}

	var file *os.File
	var err error

	for _, source := range logSources {
		file, err = os.Open(source)
		if err == nil {
			logger.Info("kernlog", "Monitoring kernel log", "source", source)
			break
		}
	}

	if file == nil {
		logger.Error("kernlog", "Could not open any kernel log source", "error", err.Error())
		return
	}
	defer file.Close()

	// Seek to end of file to only read new entries
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)

	// Use a ticker to periodically check for new log entries
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-k.stopCh:
			return
		case <-ticker.C:
			for scanner.Scan() {
				line := scanner.Text()
				k.parseAndLogFirewallEvent(line)
			}
		}
	}
}

func (k *KernelLogMonitor) parseAndLogFirewallEvent(line string) {
	// Only process QFF-related kernel messages
	if !strings.Contains(line, "QFF-") {
		return
	}

	matches := qffLogPattern.FindStringSubmatch(line)
	if len(matches) < 10 {
		return
	}

	action := matches[1]   // DROP, ACCEPT, REJECT
	ruleType := matches[2] // INPUT, OUTPUT, BLACKLIST, etc.
	port := matches[3]     // Port number (if available)
	inIface := matches[4]  // Input interface
	outIface := matches[5] // Output interface
	srcIP := matches[7]    // Source IP
	dstIP := matches[8]    // Destination IP
	protocol := matches[9] // TCP, UDP, ICMP
	srcPort := matches[10] // Source port
	dstPort := matches[11] // Destination port

	// Determine direction
	direction := "UNKNOWN"
	if inIface != "" {
		direction = "INPUT"
	} else if outIface != "" {
		direction = "OUTPUT"
	}

	// Format the log message for journald
	var logMsg string
	if port != "" {
		logMsg = fmt.Sprintf("FIREWALL %s %s port %s/%s: %s -> %s",
			action, direction, port, strings.ToLower(protocol), srcIP, dstIP)
	} else {
		logMsg = fmt.Sprintf("FIREWALL %s %s %s: %s -> %s",
			action, direction, strings.ToLower(protocol), srcIP, dstIP)
	}

	// Log to journald with structured data
	fields := []interface{}{
		"action", action,
		"direction", direction,
		"protocol", strings.ToLower(protocol),
		"src_ip", srcIP,
		"dst_ip", dstIP,
		"rule_type", ruleType,
	}

	if port != "" {
		fields = append(fields, "port", port)
	}
	if srcPort != "" {
		fields = append(fields, "src_port", srcPort)
	}
	if dstPort != "" {
		fields = append(fields, "dst_port", dstPort)
	}
	if inIface != "" {
		fields = append(fields, "in_interface", inIface)
	}
	if outIface != "" {
		fields = append(fields, "out_interface", outIface)
	}

	// Use appropriate log level based on action
	switch action {
	case "DROP", "REJECT":
		logger.Warn("firewall", logMsg, fields...)
	case "ACCEPT":
		logger.Info("firewall", logMsg, fields...)
	default:
		logger.Info("firewall", logMsg, fields...)
	}
}
