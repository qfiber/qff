// cmd/qff-engine/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"qff/internal/api"
	"qff/internal/config"
	"qff/internal/firewall"
	"qff/internal/geoip"
	"qff/internal/ips"
	"qff/internal/logger"
	"qff/internal/monitor"
	"qff/internal/notify"
)

const (
	Version           = "1.0.0"
	DefaultConfigPath = "/etc/qff/qff.conf"
	ShutdownTimeout         = 30 * time.Second
	ConnectivityTestTimeout = 5 * time.Second
)

// App encapsulates the entire application state
type App struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc

	// Core components
	notifier      *notify.Notifier
	geoipMgr      *geoip.GeoIPManager
	enhancedGeoIP *geoip.EnhancedGeoIPManager
	firewallMgr   *firewall.NFTManager
	ipsManager    *ips.IPSManager
	systemMonitor *monitor.SystemMonitor
	apiServer     *api.APIServer

	// Synchronization
	wg           sync.WaitGroup
	shutdownOnce sync.Once
}

func main() {
	// Parse command line flags
	flags := parseFlags()

	if flags.version {
		fmt.Printf("qff-engine v%s\n", Version)
		os.Exit(0)
	}

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &App{
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize and run application
	if err := app.initialize(flags); err != nil {
		logger.Error("main", "Failed to initialize application", "error", err.Error())
		os.Exit(1)
	}

	// Start all services concurrently
	if err := app.start(); err != nil {
		logger.Error("main", "Failed to start services", "error", err.Error())
		os.Exit(1)
	}

	logger.Info("main", "qff-engine started successfully", "version", Version, "pid", os.Getpid())

	// Wait for shutdown signal
	app.waitForShutdown()

	// Graceful shutdown
	app.shutdown()
	logger.Info("main", "qff-engine shutdown completed")
}

type flags struct {
	configPath string
	version    bool
	testMode   bool
}

func parseFlags() *flags {
	var f flags
	flag.StringVar(&f.configPath, "config", DefaultConfigPath, "Configuration file path")
	flag.BoolVar(&f.version, "version", false, "Show version information")
	flag.BoolVar(&f.testMode, "test", false, "Run in test mode")
	flag.Parse()
	return &f
}

func (app *App) initialize(flags *flags) error {
	// Pre-flight checks
	if err := preFlightChecks(); err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	// Load and validate configuration
	cfg, err := config.LoadConfig(flags.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", flags.configPath, err)
	}

	app.cfg = cfg

	// Set the log level based on the configuration
	if app.cfg.Firewall.LogLevel != "" {
		logger.SetLevel(app.cfg.Firewall.LogLevel)
	}

	logger.Info("main", "Configuration loaded and validated", "config_path", flags.configPath)

	// Handle test mode BEFORE initializing components with the new config
	if flags.testMode || app.cfg.TestMode.EnableTestMode {
		tempFwMgr := firewall.NewNFTManager(app.cfg)
		originalState, err := tempFwMgr.BackupCurrentState()
		if err != nil {
			return fmt.Errorf("failed to backup firewall state for test mode: %w", err)
		}
		app.setupTestModeRevert(originalState)
	}

	// Initialize components in dependency order
	if err := app.initializeComponents(); err != nil {
		return fmt.Errorf("component initialization failed: %w", err)
	}

	return nil
}

func preFlightChecks() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("QFF requires Linux operating system")
	}
	if err := firewall.CheckNFTablesAvailable(); err != nil {
		return fmt.Errorf("nftables check failed: %w", err)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("QFF requires root privileges")
	}
	return nil
}

func (app *App) initializeComponents() error {
	app.notifier = notify.NewNotifier(&app.cfg.Notification)

	app.geoipMgr = geoip.NewGeoIPManager(&app.cfg.GeoIP)
	if err := app.geoipMgr.Initialize(); err != nil {
		logger.Warn("main", "GeoIP initialization failed", "error", err.Error())
	} else {
		if app.cfg.GeoIP.MaxMindAPIKey != "" {
			app.geoipMgr.EnableAutoDownload(app.cfg.GeoIP.MaxMindAPIKey)
		}
		app.enhancedGeoIP = geoip.NewEnhancedGeoIPManager(app.geoipMgr, &app.cfg.GeoIP)
		if err := app.enhancedGeoIP.Initialize(); err != nil {
			logger.Warn("main", "Enhanced GeoIP initialization failed", "error", err.Error())
		}
	}

	app.firewallMgr = firewall.NewNFTManager(app.cfg)
	if err := app.firewallMgr.Initialize(); err != nil {
		return fmt.Errorf("firewall initialization failed: %w", err)
	}

	if err := app.firewallMgr.WhitelistCurrentUser(); err != nil {
		logger.Warn("main", "Failed to auto-whitelist current user", "error", err.Error())
	}

	app.ipsManager = ips.NewIPSManager(app.cfg, app.firewallMgr, app.notifier, app.enhancedGeoIP)

	systemMonitor, err := monitor.NewSystemMonitor(&app.cfg.Monitor, app.notifier)
	if err != nil {
		return fmt.Errorf("system monitor initialization failed: %w", err)
	}
	app.systemMonitor = systemMonitor

	app.apiServer = api.NewAPIServer(app.cfg, app.firewallMgr, app.systemMonitor, app.ipsManager, app.enhancedGeoIP)

	logger.Info("main", "All components initialized successfully")
	return nil
}

func (app *App) start() error {
	// Start IPS manager
	if app.ipsManager != nil {
		if err := app.ipsManager.Start(); err != nil {
			logger.Error("main", "Failed to start IPS manager", "error", err.Error())
			// Continue without IPS - firewall can still function
		}
		return nil
	}

	// Start system monitor
	if app.systemMonitor != nil {
		app.systemMonitor.Start()
	}

	// Start API server in a separate goroutine
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()

		// Listen for context cancellation
		go func() {
			<-app.ctx.Done()
			logger.Info("api", "Context cancelled, API server should shutdown")
		}()

		// Start the server - this will block until shutdown
		apiPort := 8080 // Default port
		if app.cfg != nil && app.cfg.Server.APIPort != 0 {
			apiPort = app.cfg.Server.APIPort
		}
		addr := fmt.Sprintf(":%d", apiPort)

		// Start the server - this will block until shutdown
		if err := app.apiServer.Start(addr); err != nil {
			logger.Error("main", "API server failed", "address", addr, "error", err.Error())
			app.cancel() // Trigger shutdown if API server fails
		}
	}()

	return nil
}

func (app *App) waitForShutdown() {
	// Create signal channel
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	select {
	case sig := <-sigCh:
		logger.Info("main", "Received shutdown signal", "signal", sig.String())
	case <-app.ctx.Done():
		logger.Info("main", "Context cancelled, initiating shutdown")
	}
}

func (app *App) shutdown() {
	app.shutdownOnce.Do(func() {
		logger.Info("main", "Starting graceful shutdown")

		// Cancel context to stop all operations
		app.cancel()

		// Create shutdown timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()

		// Shutdown components in reverse dependency order
		done := make(chan struct{})
		go func() {
			defer close(done)
			app.shutdownComponents()
			app.wg.Wait()
		}()

		select {
		case <-done:
			logger.Info("main", "Graceful shutdown completed")
		case <-shutdownCtx.Done():
			logger.Warn("main", "Shutdown timeout exceeded, forcing exit")
		}
	})
}

func (app *App) shutdownComponents() {
	// Stop API server first to prevent new requests
	if app.apiServer != nil {
		// If APIServer doesn't have a Stop method, we'll use context cancellation
		// The server should be listening for app.ctx.Done()
		logger.Info("shutdown", "Stopping API server")
	}

	// Stop monitoring and detection services
	if app.systemMonitor != nil {
		app.systemMonitor.Stop()
	}

	if app.ipsManager != nil {
		app.ipsManager.Stop()
	}

	// Close GeoIP resources
	if app.enhancedGeoIP != nil {
		app.enhancedGeoIP.Stop()
	}

	if app.geoipMgr != nil {
		app.geoipMgr.Close()
	}

	if app.firewallMgr != nil {
		logger.Info("shutdown", "Flushing all firewall rules")
		if err := app.firewallMgr.FlushRuleset(); err != nil {
			logger.Error("shutdown", "Failed to flush firewall rules on exit", "error", err.Error())
		}
	}

	// Firewall manager cleanup happens automatically via defer in main
}

func (app *App) setupTestModeRevert(originalState *firewall.FirewallState) {
	if !app.cfg.TestMode.EnableTestMode {
		return
	}

	logger.Info("testmode", "Test mode is active", "duration", app.cfg.TestMode.TestDuration)

	// Setup auto-revert if enabled
	if app.cfg.TestMode.RevertOnFailure {
		time.AfterFunc(app.cfg.TestMode.TestDuration, func() {
			logger.Info("testmode", "Test mode timeout reached. Checking connectivity...")

			// Re-run connectivity tests
			allTestsPassed := true
			results := app.runConnectivityTests(app.cfg.TestMode.TestConnections)
			for host, success := range results {
				if !success {
					allTestsPassed = false
					logger.Warn("testmode", "Connectivity test failed", "host", host)
				} else {
					logger.Info("testmode", "Connectivity test passed", "host", host)
				}
			}

			if !allTestsPassed {
				logger.Warn("testmode", "One or more connectivity tests failed. REVERTING firewall configuration.")
				// Use a new firewall manager instance to restore the state
				revertMgr := firewall.NewNFTManager(app.cfg)
				if err := revertMgr.RestoreState(originalState); err != nil {
					logger.Error("testmode", "CRITICAL: Failed to restore firewall state!", "error", err.Error())
				} else {
					logger.Info("testmode", "Firewall configuration successfully reverted to previous state.")
				}
			} else {
				logger.Info("testmode", "All connectivity tests passed. Keeping new configuration.")
			}
		})
	}
}

func (app *App) runConnectivityTests(hosts []string) map[string]bool {
	if len(hosts) == 0 {
		return make(map[string]bool)
	}

	results := make(map[string]bool, len(hosts))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Test connectivity concurrently for better performance
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			success := testConnectivity(h, ConnectivityTestTimeout)
			mu.Lock()
			results[h] = success
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return nil
}

func testConnectivity(host string, timeout time.Duration) bool {
	// Add default port if not specified
	if _, _, err := net.SplitHostPort(host); err != nil {
		// Try HTTPS first, then HTTP
		if testSingleConnection(host+":443", timeout) {
			return true
		}
		host += ":80"
	}

	return false
}

func testSingleConnection(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return false
}
