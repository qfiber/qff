// internal/api/api.go
package api

import (
	"encoding/json"
	"fmt"      // Required for error wrapping
	"net"      // Required for socket communication
	"net/http"
	"os"       // Required for file operations on the socket
	"os/user"  // Required for group lookup
	"strconv"
	"strings"
	"time"

	"qff/internal/config"
	"qff/internal/firewall"
	"qff/internal/geoip"
	"qff/internal/ips"
	"qff/internal/logger"
	"qff/internal/monitor"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type APIServer struct {
	config        *config.Config
	firewall      *firewall.NFTManager
	monitor       *monitor.SystemMonitor
	ipsManager    *ips.IPSManager
	enhancedGeoIP *geoip.EnhancedGeoIPManager
	router        *mux.Router
	startTime     time.Time
}

type StatusResponse struct {
	Status           string                 `json:"status"`
	Version          string                 `json:"version"`
	Uptime           string                 `json:"uptime"`
	GeoIPAvailable   bool                   `json:"geoip_available"`
	TemporaryEntries int                    `json:"temporary_entries"`
	Config           map[string]interface{} `json:"config,omitempty"`
}

type MetricsResponse struct {
	SystemMetrics   map[string]interface{} `json:"system_metrics"`
	FirewallMetrics map[string]interface{} `json:"firewall_metrics"`
}

// getGroupId looks up a group by name and returns its GID.
func getGroupId(groupName string) (int, bool) {
	g, err := user.LookupGroup(groupName)
	if err != nil {
		logger.Warn("api", "Could not find group for socket permissions", "group", groupName, "error", err)
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		logger.Warn("api", "Could not parse GID for group", "group", groupName, "error", err)
		return 0, false
	}
	return gid, true
}

func NewAPIServer(cfg *config.Config, fw *firewall.NFTManager, mon *monitor.SystemMonitor, ipsMgr *ips.IPSManager, geoipMgr *geoip.EnhancedGeoIPManager) *APIServer {
	api := &APIServer{
		config:        cfg,
		firewall:      fw,
		monitor:       mon,
		ipsManager:    ipsMgr,
		enhancedGeoIP: geoipMgr,
		router:        mux.NewRouter(),
		startTime:     time.Now(),
	}

	api.setupRoutes()
	return api
}

// Start now listens on a Unix socket specified by the addr (file path).
func (a *APIServer) Start(addr string) error {
	logger.Info("api", "Starting API server on Unix socket", "path", addr)

	// Remove the socket file if it already exists to prevent errors on restart
	if err := os.RemoveAll(addr); err != nil {
		return err
	}

	// Listen on the Unix socket
	listener, err := net.Listen("unix", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %w", err)
	}
	defer listener.Close()

	// Set file permissions so only root and a specific group can access it.
	// This requires an admin to create the 'qff-admin' group and add users to it.
	if err := os.Chmod(addr, 0770); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}
	// Optional: Change group ownership to a dedicated admin group.
	if gid, ok := getGroupId("qff-admin"); ok {
		if err := os.Chown(addr, 0, gid); err != nil { // 0 for root user
			logger.Warn("api", "Failed to set group ownership on socket", "error", err)
		}
	}

	// Serve HTTP requests on the listener
	return http.Serve(listener, a.router)
}

// --- All other handler functions remain exactly the same ---
// The change to the Start method is all that's needed on the server side.
// The rest of the file is included for completeness.

func (a *APIServer) handleGeoIPCheck(w http.ResponseWriter, r *http.Request) {
	if a.enhancedGeoIP == nil {
		a.writeErrorResponse(w, "GeoIP manager not available", http.StatusServiceUnavailable)
		return
	}
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	country := a.enhancedGeoIP.GetCountry(ip)
	isBlocked := a.enhancedGeoIP.IsBlocked(ip)

	a.writeJSONResponse(w, map[string]interface{}{
		"ip":         ip.String(),
		"country":    country,
		"is_blocked": isBlocked,
	})
}

func (a *APIServer) handleVPNCheck(w http.ResponseWriter, r *http.Request) {
	if a.enhancedGeoIP == nil {
		a.writeErrorResponse(w, "GeoIP manager not available", http.StatusServiceUnavailable)
		return
	}
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	result := a.enhancedGeoIP.CheckVPN(ip)
	a.writeJSONResponse(w, result)
}

func (a *APIServer) handleTempBlockAdd(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	durationStr := r.URL.Query().Get("duration")
	if durationStr == "" {
		a.writeErrorResponse(w, "duration parameter is required", http.StatusBadRequest)
		return
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		a.writeErrorResponse(w, "invalid duration format", http.StatusBadRequest)
		return
	}

	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "Manual temporary block via API"
	}

	if err := a.ipsManager.AddTempBlock(ip, duration, reason); err != nil {
		a.writeErrorResponse(w, "Failed to temporarily block IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":   "temporarily blocked",
		"ip":       ip.String(),
		"duration": duration.String(),
		"reason":   reason,
	})
}

func (a *APIServer) handleTempRemove(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.ipsManager.RemoveTempRule(ip); err != nil {
		a.writeErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status": "temporary rule removed",
		"ip":     ip.String(),
	})
}

func (a *APIServer) setupRoutes() {
	a.router.HandleFunc("/status", a.handleStatus).Methods("GET")
	a.router.HandleFunc("/metrics", a.handleMetrics).Methods("GET")
	a.router.HandleFunc("/reload", a.handleReload).Methods("POST")

	// IP management
	a.router.HandleFunc("/whitelist", a.handleWhitelistAdd).Methods("POST")
	a.router.HandleFunc("/whitelist", a.handleWhitelistRemove).Methods("DELETE")
	a.router.HandleFunc("/blacklist", a.handleBlacklistAdd).Methods("POST")
	a.router.HandleFunc("/blacklist", a.handleBlacklistRemove).Methods("DELETE")

	// DNS management
	a.router.HandleFunc("/dns/hosts", a.handleDNSHosts).Methods("GET")
	a.router.HandleFunc("/dns/add", a.handleDNSAdd).Methods("POST")

	// Prometheus metrics
	a.router.Handle("/prometheus", promhttp.Handler())

	// IPS management endpoints
	a.router.HandleFunc("/api/ips/blocked", a.handleIPSBlocked).Methods("GET")
	a.router.HandleFunc("/api/ips/whitelist", a.handleIPSWhitelist).Methods("GET")
	a.router.HandleFunc("/api/ips/unblock", a.handleIPSUnblock).Methods("POST")
	a.router.HandleFunc("/api/ips/whitelist/add", a.handleIPSWhitelistAdd).Methods("POST")
	a.router.HandleFunc("/api/ips/whitelist/remove", a.handleIPSWhitelistRemove).Methods("DELETE")
	a.router.HandleFunc("/api/ips/stats", a.handleIPSStats).Methods("GET")
	a.router.HandleFunc("/api/ips/tempblock", a.handleTempBlockAdd).Methods("POST")
	a.router.HandleFunc("/api/ips/tempremove", a.handleTempRemove).Methods("DELETE")

	// Enhanced GeoIP endpoints
	a.router.HandleFunc("/api/geoip/check", a.handleGeoIPCheck).Methods("GET")
	a.router.HandleFunc("/api/geoip/vpn-check", a.handleVPNCheck).Methods("GET")
	a.router.HandleFunc("/api/geoip/stats", a.handleGeoIPStats).Methods("GET")

	a.router.HandleFunc("/api/ports/list", a.handlePortsList).Methods("GET")
	a.router.HandleFunc("/api/ports/add", a.handlePortAdd).Methods("POST")
	a.router.HandleFunc("/api/ports/remove", a.handlePortRemove).Methods("DELETE")

	// Middleware
	a.router.Use(a.loggingMiddleware)
	a.router.Use(a.corsMiddleware)
}

func (a *APIServer) handleGeoIPStats(w http.ResponseWriter, r *http.Request) {
	a.writeJSONResponse(w, map[string]interface{}{
		"message": "Enhanced GeoIP stats endpoint - implementation needed",
	})
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(a.startTime)

	response := StatusResponse{
		Status:         "running",
		Version:        "1.0.0",
		Uptime:         uptime.String(),
		GeoIPAvailable: a.config.GeoIP.MMDBPath != "",
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	systemMetrics, err := a.monitor.GetMetrics()
	if err != nil {
		logger.Error("api", "Failed to get system metrics", "error", err)
	}

	systemMetricsInterface := make(map[string]interface{})
	for k, v := range systemMetrics {
		systemMetricsInterface[k] = v
	}

	firewallMetrics, _ := a.firewall.GetStats()

	response := MetricsResponse{
		SystemMetrics:   systemMetricsInterface,
		FirewallMetrics: firewallMetrics,
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleReload(w http.ResponseWriter, r *http.Request) {
	logger.Info("api", "Reloading configuration via API")

	if err := a.firewall.Reload(); err != nil {
		logger.Error("api", "Failed to reload firewall", "error", err.Error())
		a.writeErrorResponse(w, "Failed to reload", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "reloaded"})
}

func (a *APIServer) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.AddWhitelistIP(ip); err != nil {
		logger.Error("api", "Failed to add IP to whitelist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to add IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "added", "ip": ip.String()})
}

func (a *APIServer) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.RemoveWhitelistIP(ip); err != nil {
		logger.Error("api", "Failed to remove IP from whitelist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to remove IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "removed", "ip": ip.String()})
}

func (a *APIServer) handleBlacklistAdd(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.AddBlacklistIP(ip); err != nil {
		logger.Error("api", "Failed to add IP to blacklist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to add IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "added", "ip": ip.String()})
}

func (a *APIServer) handleBlacklistRemove(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.RemoveBlacklistIP(ip); err != nil {
		logger.Error("api", "Failed to remove IP from blacklist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to remove IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "removed", "ip": ip.String()})
}

func (a *APIServer) handleDNSHosts(w http.ResponseWriter, r *http.Request) {
	hosts := a.firewall.GetDynamicHosts()
	a.writeJSONResponse(w, map[string]interface{}{
		"dynamic_hosts": hosts,
	})
}

func (a *APIServer) handleDNSAdd(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		a.writeErrorResponse(w, "hostname parameter required", http.StatusBadRequest)
		return
	}

	if err := a.firewall.AddDynamicHost(hostname); err != nil {
		a.writeErrorResponse(w, "Failed to add hostname", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status":   "added",
		"hostname": hostname,
	})
}

func (a *APIServer) parseIPFromQuery(w http.ResponseWriter, r *http.Request) net.IP {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		a.writeErrorResponse(w, "IP parameter required", http.StatusBadRequest)
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		a.writeErrorResponse(w, "Invalid IP address", http.StatusBadRequest)
		return nil
	}

	return ip
}

func (a *APIServer) writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (a *APIServer) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (a *APIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		logger.Info("api", "HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", duration.String(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

func (a *APIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *APIServer) autoWhitelistClient(r *http.Request) {
	clientIP := GetClientIP(r)
	if clientIP != nil && !clientIP.IsLoopback() {
		if err := a.firewall.AddWhitelistIP(clientIP); err != nil {
			logger.Error("api", "Failed to auto-whitelist client", "ip", clientIP.String(), "error", err.Error())
		} else {
			logger.Info("api", "Auto-whitelisted API client", "ip", clientIP.String())
		}
	}
}

func GetClientIP(r *http.Request) net.IP {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := net.ParseIP(strings.TrimSpace(ips[0]))
			if ip != nil {
				return ip
			}
		}
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}

	return net.ParseIP(host)
}

func (a *APIServer) handlePortsList(w http.ResponseWriter, r *http.Request) {
	ports := a.firewall.ListPortRules()
	a.writeJSONResponse(w, map[string]interface{}{
		"port_rules": ports,
	})
}

func (a *APIServer) handlePortAdd(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")
	direction := r.URL.Query().Get("direction")
	action := r.URL.Query().Get("action")

	if port == "" || protocol == "" || direction == "" {
		a.writeErrorResponse(w, "Missing required parameters: port, protocol, direction", http.StatusBadRequest)
		return
	}

	if action == "" {
		action = "allow"
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		a.writeErrorResponse(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	if err := a.firewall.AddPortRule(portNum, protocol, direction, action); err != nil {
		a.writeErrorResponse(w, "Failed to add port rule", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "added",
		"port":      portNum,
		"protocol":  protocol,
		"direction": direction,
		"action":    action,
	})
}

func (a *APIServer) handlePortRemove(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")
	direction := r.URL.Query().Get("direction")

	if port == "" || protocol == "" || direction == "" {
		a.writeErrorResponse(w, "Missing required parameters: port, protocol, direction", http.StatusBadRequest)
		return
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		a.writeErrorResponse(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	if err := a.firewall.RemovePortRule(portNum, protocol, direction); err != nil {
		a.writeErrorResponse(w, "Failed to remove port rule", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "removed",
		"port":      portNum,
		"protocol":  protocol,
		"direction": direction,
	})
}

func (a *APIServer) handleIPSBlocked(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	blocked := a.ipsManager.GetBlockedIPs()
	a.writeJSONResponse(w, map[string]interface{}{
		"blocked_ips": blocked,
		"count":       len(blocked),
	})
}

func (a *APIServer) handleIPSWhitelist(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	whitelist := a.ipsManager.GetWhitelistedIPs()
	a.writeJSONResponse(w, map[string]interface{}{
		"whitelisted_ips": whitelist,
		"count":           len(whitelist),
	})
}

func (a *APIServer) handleIPSUnblock(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.ipsManager.UnblockIP(ip); err != nil {
		a.writeErrorResponse(w, "Failed to unblock IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status": "unblocked",
		"ip":     ip.String(),
	})
}

func (a *APIServer) handleIPSWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	permanent := r.URL.Query().Get("permanent") == "true"
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "Manual whitelist via API"
	}

	if err := a.ipsManager.AddWhitelist(ip, permanent, reason); err != nil {
		a.writeErrorResponse(w, "Failed to whitelist IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "whitelisted",
		"ip":        ip.String(),
		"permanent": permanent,
		"reason":    reason,
	})
}

func (a *APIServer) handleIPSWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.ipsManager.RemoveWhitelist(ip); err != nil {
		a.writeErrorResponse(w, "Failed to remove whitelist", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status": "removed",
		"ip":     ip.String(),
	})
}

func (a *APIServer) handleIPSStats(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	stats := a.ipsManager.GetStats()
	a.writeJSONResponse(w, stats)
}