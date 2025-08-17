// internal/monitor/monitor.go
package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
	"qff/internal/notify"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

const (
	defaultCollectionInterval = 30 * time.Second
	defaultAlertCooldown      = 10 * time.Minute
)

type SystemMonitor struct {
	config        *config.MonitorConfig
	notifier      *notify.Notifier
	metrics       *MonitorMetrics
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	alertCooldown *sync.Map // thread-safe cooldown tracking
}

type MonitorMetrics struct {
	cpuUsage    prometheus.Gauge
	memoryUsage prometheus.Gauge
	diskUsage   prometheus.Gauge
	connections prometheus.Gauge
	bytesSent   prometheus.Gauge
	bytesRecv   prometheus.Gauge
	packetsSent prometheus.Gauge
	packetsRecv prometheus.Gauge
}

func NewSystemMonitor(cfg *config.MonitorConfig, notifier *notify.Notifier) (*SystemMonitor, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if notifier == nil {
		return nil, ErrNilNotifier
	}

	metrics := &MonitorMetrics{
		cpuUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_cpu_usage_percent",
			Help: "Current system-wide CPU usage percentage",
		}),
		memoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_memory_usage_percent",
			Help: "Current system-wide memory usage percentage",
		}),
		diskUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_disk_usage_percent",
			Help: "Current disk usage percentage for the root filesystem",
		}),
		connections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_active_connections",
			Help: "Number of active network connections",
		}),
		// +++ ADD THE INITIALIZATIONS BELOW +++
		bytesSent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_network_bytes_sent_total",
			Help: "Total number of bytes sent over the network.",
		}),
		bytesRecv: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_network_bytes_received_total",
			Help: "Total number of bytes received over the network.",
		}),
		packetsSent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_network_packets_sent_total",
			Help: "Total number of packets sent over the network.",
		}),
		packetsRecv: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qff_network_packets_received_total",
			Help: "Total number of packets received over the network.",
		}),
	}

	_ = prometheus.Register(metrics.cpuUsage)
	_ = prometheus.Register(metrics.memoryUsage)
	_ = prometheus.Register(metrics.diskUsage)
	_ = prometheus.Register(metrics.connections)
	_ = prometheus.Register(metrics.bytesSent)
	_ = prometheus.Register(metrics.bytesRecv)
	_ = prometheus.Register(metrics.packetsSent)
	_ = prometheus.Register(metrics.packetsRecv)

	if cfg.AlertCooldown == 0 {
        cfg.AlertCooldown = defaultAlertCooldown
    }

    ctx, cancel := context.WithCancel(context.Background())

    return &SystemMonitor{
		config:        cfg,
		notifier:      notifier,
		metrics:       metrics,
		ctx:           ctx,
		cancel:        cancel,
		alertCooldown: &sync.Map{},
	}, nil
}

func (m *SystemMonitor) Start() {
	if !m.config.EnableResourceMonitoring {
		logger.Debug("monitor", "Resource monitoring disabled in config")
		return
	}

	interval := defaultCollectionInterval

	logger.Info("monitor", "Starting system monitor", "interval", interval)

	m.wg.Add(1)
	go m.runMonitoringLoop(interval)
}

func (m *SystemMonitor) runMonitoringLoop(interval time.Duration) {
	defer m.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectAndAlert()
		case <-m.ctx.Done():
			logger.Info("monitor", "Stopping monitoring loop")
			return
		}
	}
}

func (m *SystemMonitor) collectAndAlert() {
	var wg sync.WaitGroup

	// Always collect all metrics for Prometheus
	// --- CHANGE 4 to 5 ---
	wg.Add(5)
	go func() {
		defer wg.Done()
		m.checkCPUUsage()
	}()
	go func() {
		defer wg.Done()
		m.checkMemoryUsage()
	}()
	go func() {
		defer wg.Done()
		m.checkDiskUsage()
	}()
	go func() {
		defer wg.Done()
		m.checkConnections()
	}()
	go func() {
		defer wg.Done()
		m.checkNetworkIO()
	}()

	wg.Wait()
}

func (m *SystemMonitor) checkCPUUsage() {
	cpuUsage, err := m.getCPUUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get CPU usage", "error", err)
		return
	}

	m.metrics.cpuUsage.Set(cpuUsage)

	if m.config.CPUAlert && cpuUsage > m.config.CPUThreshold && m.shouldAlert("cpu") {
		m.notifier.SendAlert("High CPU Usage", map[string]interface{}{
			"cpu_usage": cpuUsage,
			"threshold": m.config.CPUThreshold,
		})
		m.alertCooldown.Store("cpu", time.Now())
	}
}

func (m *SystemMonitor) checkMemoryUsage() {
	memUsage, err := m.getMemoryUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get memory usage", "error", err)
		return
	}

	m.metrics.memoryUsage.Set(memUsage)

	if m.config.MemoryAlert && memUsage > m.config.MemoryThreshold && m.shouldAlert("memory") {
		m.notifier.SendAlert("High Memory Usage", map[string]interface{}{
			"memory_usage": memUsage,
			"threshold":    m.config.MemoryThreshold,
		})
		m.alertCooldown.Store("memory", time.Now())
	}
}

func (m *SystemMonitor) checkDiskUsage() {
	diskUsage, err := m.getDiskUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get disk usage", "error", err)
		return
	}

	m.metrics.diskUsage.Set(diskUsage)

	if m.config.DiskAlert && diskUsage > m.config.DiskThreshold && m.shouldAlert("disk") {
		m.notifier.SendAlert("High Disk Usage", map[string]interface{}{
			"disk_usage": diskUsage,
			"threshold":  m.config.DiskThreshold,
		})
		m.alertCooldown.Store("disk", time.Now())
	}
}

func (m *SystemMonitor) checkConnections() {
	connections, err := m.getActiveConnections()
	if err != nil {
		logger.Error("monitor", "Failed to get active connections", "error", err)
		return
	}
	m.metrics.connections.Set(float64(connections))
}

func (m *SystemMonitor) checkNetworkIO() {
	bytesSent, bytesRecv, packetsSent, packetsRecv, err := getNetworkIO()
	if err != nil {
		logger.Error("monitor", "Failed to get network I/O stats", "error", err)
		return
	}
	m.metrics.bytesSent.Set(float64(bytesSent))
	m.metrics.bytesRecv.Set(float64(bytesRecv))
	m.metrics.packetsSent.Set(float64(packetsSent))
	m.metrics.packetsRecv.Set(float64(packetsRecv))
}

func (m *SystemMonitor) shouldAlert(alertType string) bool {
	lastAlert, exists := m.alertCooldown.Load(alertType)
	if !exists {
		return true
	}

	return time.Since(lastAlert.(time.Time)) > m.config.AlertCooldown
}

func (m *SystemMonitor) getCPUUsage() (float64, error) {
	percentages, err := cpu.Percent(0, false)
	if err != nil {
		return 0, err
	}
	if len(percentages) == 0 {
		return 0, errors.New("could not retrieve CPU percentage")
	}
	return percentages[0], nil
}

func (m *SystemMonitor) getMemoryUsage() (float64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return vmStat.UsedPercent, nil
}

func (m *SystemMonitor) getDiskUsage() (float64, error) {
	usageStat, err := disk.Usage("/")
	if err != nil {
		return 0, err
	}
	return usageStat.UsedPercent, nil
}

func getNetworkIO() (bytesSent, bytesRecv, packetsSent, packetsRecv uint64, err error) {
	// 'false' gets stats per network interface, which we then sum up.
	ioCounters, err := net.IOCounters(false)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	for _, counter := range ioCounters {
		bytesSent += counter.BytesSent
		bytesRecv += counter.BytesRecv
		packetsSent += counter.PacketsSent
		packetsRecv += counter.PacketsRecv
	}

	return bytesSent, bytesRecv, packetsSent, packetsRecv, nil
}

func (m *SystemMonitor) getActiveConnections() (int, error) {
	conns, err := net.Connections("all")
	if err != nil {
		return 0, err
	}
	return len(conns), nil
}

func (m *SystemMonitor) Stop() {
	m.cancel()
	m.wg.Wait()
	logger.Info("monitor", "System monitor stopped")
}

func (m *SystemMonitor) GetMetrics() (map[string]float64, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	metrics := make(map[string]float64)
	var errs []error

	collect := func(name string, fn func() (float64, error)) {
		defer wg.Done()
		value, err := fn()
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			mu.Unlock()
			return
		}
		mu.Lock()
		metrics[name] = value
		mu.Unlock()
	}

	collectInt := func(name string, fn func() (int, error)) {
		defer wg.Done()
		value, err := fn()
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			mu.Unlock()
			return
		}
		mu.Lock()
		metrics[name] = float64(value)
		mu.Unlock()
	}

	wg.Add(5)
	go collect("cpu_usage", m.getCPUUsage)
	go collect("memory_usage", m.getMemoryUsage)
	go collect("disk_usage", m.getDiskUsage)
	go collectInt("active_connections", m.getActiveConnections)
	go func() {
		defer wg.Done()
		bytesSent, bytesRecv, packetsSent, packetsRecv, err := getNetworkIO()
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("network_io: %w", err))
			mu.Unlock()
			return
		}
		mu.Lock()
		metrics["network_bytes_sent"] = float64(bytesSent)
		metrics["network_bytes_recv"] = float64(bytesRecv)
		metrics["network_packets_sent"] = float64(packetsSent)
		metrics["network_packets_recv"] = float64(packetsRecv)
		mu.Unlock()
	}()
	wg.Wait()

	if len(errs) > 0 {
		return metrics, ErrPartialMetrics{Errors: errs}
	}

	return metrics, nil
}

// Custom errors for better error handling
var (
	ErrNilConfig   = errors.New("monitor config cannot be nil")
	ErrNilNotifier = errors.New("notifier cannot be nil")
)

type ErrPartialMetrics struct {
	Errors []error
}

func (e ErrPartialMetrics) Error() string {
	return fmt.Sprintf("partial metrics collected with %d errors", len(e.Errors))
}
