// cmd/qff/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net" // Required for socket communication
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"qff/internal/config"
)

const (
	Version           = "1.0.0"
	ServiceName       = "qff"
	DefaultSocketPath = "/var/run/qff.sock" // Default path for the socket
)

// CLI represents the command-line interface
type CLI struct {
	client *APIClient
	config *config.CLIConfig
}

// APIClient handles communication with the QFF API over a socket
type APIClient struct {
	// The baseURL is now a dummy value; the client connects directly to the socket.
	baseURL string
	client  *http.Client
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Handler     func(*CLI, []string) error
}

// Define flags for quick actions
var (
	allowFlag      = flag.String("a", "", "Permanently allow an IP address.")
	denyFlag       = flag.String("d", "", "Permanently deny an IP address.")
	tempAllowFlag  = flag.String("ta", "", "Temporarily allow an IP. Usage: -ta \"<ip> <duration> [note]\"")
	tempDenyFlag   = flag.String("td", "", "Temporarily deny an IP. Usage: -td \"<ip> <duration> [note]\"")
	tempRemoveFlag = flag.String("tr", "", "Remove a temporary rule for an IP.")
)

func main() {
	// Note: You will need to update LoadCLIConfig to load a SocketPath instead of APIBase.
	cliConfig, err := config.LoadCLIConfig("/etc/qff/cli.conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CLI config: %v\n", err)
		os.Exit(1)
	}

	// Use default socket path if not specified in config
	socketPath := cliConfig.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	cli := &CLI{
		client: NewAPIClient(socketPath, cliConfig.Timeout),
		config: cliConfig,
	}

	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// NewAPIClient creates a client that communicates over a Unix socket.
func NewAPIClient(socketPath string, timeout time.Duration) *APIClient {
	// The HTTP client is configured with a custom Transport that dials the Unix socket.
	httpClient := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	return &APIClient{
		// The baseURL is a dummy value. The "unix" host is arbitrary but required
		// for the request object. Our custom transport above ignores it.
		baseURL: "http://unix",
		client:  &httpClient,
	}
}

func (cli *CLI) Run(args []string) error {
	// Parse flags first
	flag.CommandLine.Parse(args)

	// Check if any of our new flags were used
	if *allowFlag != "" {
		return cli.handleAllow(*allowFlag)
	}
	if *denyFlag != "" {
		return cli.handleDeny(*denyFlag)
	}
	if *tempAllowFlag != "" {
		return cli.handleTempAllow(*tempAllowFlag)
	}
	if *tempDenyFlag != "" {
		return cli.handleTempDeny(*tempDenyFlag)
	}
	if *tempRemoveFlag != "" {
		return cli.handleTempRemove(*tempRemoveFlag)
	}

	// If no flags were used, fall back to subcommand logic
	subcommandArgs := flag.Args()
	if len(subcommandArgs) == 0 {
		return cli.showUsage()
	}

	commands := cli.getCommands()
	command := subcommandArgs[0]
	cmd, exists := commands[command]
	if !exists {
		return fmt.Errorf("unknown command: %s", command)
	}

	return cmd.Handler(cli, subcommandArgs[1:])
}

// --- New Flag Handlers ---

func (cli *CLI) handleAllow(ip string) error {
	fmt.Printf("Permanently allowing IP: %s\n", ip)
	return cli.addIPToList("whitelist", ip)
}

func (cli *CLI) handleDeny(ip string) error {
	fmt.Printf("Permanently denying IP: %s\n", ip)
	return cli.addIPToList("blacklist", ip)
}

func (cli *CLI) handleTempAllow(argsStr string) error {
	parts := strings.Fields(argsStr)
	if len(parts) < 2 {
		return fmt.Errorf("invalid usage for -ta. Expected: -ta \"<ip> <duration> [note]\"")
	}
	ip, duration := parts[0], parts[1]
	note := "Temporary allow via CLI"
	if len(parts) > 2 {
		note = strings.Join(parts[2:], " ")
	}

	fmt.Printf("Temporarily allowing IP: %s for %s. Note: %s\n", ip, duration, note)

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/whitelist/add?ip=%s&permanent=false&reason=%s", url.QueryEscape(ip), url.QueryEscape(note))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}
	fmt.Println("Successfully added temporary allow rule.")
	return nil
}

func (cli *CLI) handleTempDeny(argsStr string) error {
	parts := strings.Fields(argsStr)
	if len(parts) < 2 {
		return fmt.Errorf("invalid usage for -td. Expected: -td \"<ip> <duration> [note]\"")
	}
	ip, duration := parts[0], parts[1]
	note := "Temporary deny via CLI at " + time.Now().Format(time.RFC3339)
	if len(parts) > 2 {
		note = strings.Join(parts[2:], " ")
	}

	fmt.Printf("Temporarily denying IP: %s for %s. Note: %s\n", ip, duration, note)

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/tempblock?ip=%s&duration=%s&reason=%s", url.QueryEscape(ip), url.QueryEscape(duration), url.QueryEscape(note))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}
	fmt.Println("Successfully added temporary deny rule.")
	return nil
}

func (cli *CLI) handleTempRemove(ip string) error {
	fmt.Printf("Removing temporary rule for IP: %s\n", ip)

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/tempremove?ip=%s", url.QueryEscape(ip))
	_, err := cli.client.Delete(ctx, endpoint)
	if err != nil {
		return err
	}
	fmt.Println("Successfully removed temporary rule.")
	return nil
}

func (cli *CLI) getCommands() map[string]*Command {
	return map[string]*Command{
		"status": {
			Name:        "status",
			Description: "Show firewall status",
			Handler:     (*CLI).handleStatus,
		},
		"metrics": {
			Name:        "metrics",
			Description: "Show system metrics",
			Handler:     (*CLI).handleMetrics,
		},
		"logs": {
			Name:        "logs",
			Description: "Show recent logs",
			Handler:     (*CLI).handleLogs,
		},
		"reload": {
			Name:        "reload",
			Description: "Reload configuration",
			Handler:     (*CLI).handleReload,
		},
		"enable": {
			Name:        "enable",
			Description: "Enable and start service",
			Handler:     (*CLI).handleEnable,
		},
		"disable": {
			Name:        "disable",
			Description: "Stop and disable service",
			Handler:     (*CLI).handleDisable,
		},
		"whitelist": {
			Name:        "whitelist",
			Description: "Manage IP whitelist (use 'whitelist list')",
			Handler:     (*CLI).handleWhitelist,
		},
		"blacklist": {
			Name:        "blacklist",
			Description: "Manage IP blacklist (use 'blacklist list')",
			Handler:     (*CLI).handleBlacklist,
		},
		"ips": {
			Name:        "ips",
			Description: "IPS management commands",
			Handler:     (*CLI).handleIPS,
		},
		"ports": {
			Name:        "ports",
			Description: "Port management commands",
			Handler:     (*CLI).handlePorts,
		},
		"version": {
			Name:        "version",
			Description: "Show version information",
			Handler:     (*CLI).handleVersion,
		},
	}
}

func (cli *CLI) showUsage() error {
	fmt.Println("QFF CLI - qFibre Firewall Manager")
	fmt.Printf("Version: %s\n\n", Version)
	fmt.Println("Usage: qff-cli [flags] [command]")

	fmt.Println("\nFlags for Quick Actions:")
	flag.PrintDefaults()

	fmt.Println("\nCommands for Detailed Operations:")
	commands := cli.getCommands()
	for _, cmd := range commands {
		fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
	}

	fmt.Println("\nEnvironment Variables:")
	fmt.Println("  QFF_SOCKET_PATH   API socket path (default: /var/run/qff.sock)")
	fmt.Println("  QFF_VERBOSE       Enable verbose output (set to '1')")
	fmt.Println("\nExamples:")
	fmt.Println("  qff-cli -a 192.168.1.100")
	fmt.Println("  qff-cli -td \"8.8.8.8 1h DNS server acting up\"")
	fmt.Println("  qff-cli status")
	fmt.Println("  qff-cli ips blocked")

	return nil
}

// API Client methods
func (ac *APIClient) makeRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	fullURL := ac.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("qff-cli/%s", Version))

	resp, err := ac.client.Do(req)
	if err != nil {
		// Provide a more helpful error message for socket connection issues
		if _, ok := err.(*net.OpError); ok {
			return nil, fmt.Errorf("making request: connection to socket failed. Is the qff-engine service running and do you have permission to access the socket file?")
		}
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func (ac *APIClient) Get(ctx context.Context, endpoint string) ([]byte, error) {
	return ac.makeRequest(ctx, "GET", endpoint, nil)
}

func (ac *APIClient) Post(ctx context.Context, endpoint string, body io.Reader) ([]byte, error) {
	return ac.makeRequest(ctx, "POST", endpoint, body)
}

func (ac *APIClient) Delete(ctx context.Context, endpoint string) ([]byte, error) {
	return ac.makeRequest(ctx, "DELETE", endpoint, nil)
}

// Command handlers
func (cli *CLI) handleStatus(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/status")
	if err != nil {
		return err
	}

	var status StatusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("parsing status response: %w", err)
	}

	cli.printStatus(&status)
	return nil
}

func (cli *CLI) handleMetrics(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/metrics")
	if err != nil {
		return err
	}

	var metrics MetricsResponse
	if err := json.Unmarshal(data, &metrics); err != nil {
		return fmt.Errorf("parsing metrics response: %w", err)
	}

	cli.printMetrics(&metrics)
	return nil
}

func (cli *CLI) handleLogs(args []string) error {
	lines := cli.config.DefaultLogLines
	if len(args) > 0 {
		if l, err := strconv.Atoi(args[0]); err == nil && l > 0 {
			lines = l
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", "-u", ServiceName, "-n", strconv.Itoa(lines), "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("getting logs: %w", err)
	}

	fmt.Print(string(output))
	return nil
}

func (cli *CLI) handleReload(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	_, err := cli.client.Post(ctx, "/reload", nil)
	if err != nil {
		return err
	}

	fmt.Println("Configuration reloaded successfully")
	return nil
}

func (cli *CLI) handleEnable(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", ServiceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	fmt.Println("QFF service enabled and started")
	return nil
}

func (cli *CLI) handleDisable(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "disable", "--now", ServiceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("disabling service: %w", err)
	}

	fmt.Println("QFF service disabled and stopped")
	return nil
}

func (cli *CLI) handleVersion(args []string) error {
	fmt.Printf("qff-cli v%s\n", Version)
	return nil
}

func (cli *CLI) handleWhitelist(args []string) error {
	if len(args) > 0 && args[0] == "list" {
		return cli.listIPs("whitelist")
	}
	return fmt.Errorf("invalid command. Use 'qff-cli -a <ip>' to add, or 'qff-cli whitelist list' to view")
}

func (cli *CLI) handleBlacklist(args []string) error {
	if len(args) > 0 && args[0] == "list" {
		return cli.listIPs("blacklist")
	}
	return fmt.Errorf("invalid command. Use 'qff-cli -d <ip>' to add, or 'qff-cli blacklist list' to view")
}

func (cli *CLI) addIPToList(listType, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/%s?ip=%s", listType, url.QueryEscape(ip))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added %s to %s\n", ip, listType)
	return nil
}

func (cli *CLI) listIPs(listType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/%s", listType)
	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	cli.printIPList(listType, result)
	return nil
}

// IPS command handlers
func (cli *CLI) handleIPS(args []string) error {
	if len(args) == 0 {
		return cli.showIPSUsage()
	}

	ipsCommands := map[string]func([]string) error{
		"status":      cli.handleIPSStatus,
		"blocked":     cli.handleIPSBlocked,
		"whitelist":   cli.handleIPSWhitelist,
		"unblock":     cli.handleIPSUnblock,
		"geoip-check": cli.handleGeoIPCheck,
		"vpn-check":   cli.handleVPNCheck,
	}

	subcommand := args[0]
	handler, exists := ipsCommands[subcommand]
	if !exists {
		return fmt.Errorf("unknown IPS command: %s", subcommand)
	}

	return handler(args[1:])
}

func (cli *CLI) showIPSUsage() error {
	fmt.Println("IPS Commands:")
	fmt.Println("  ips status                          Show IPS status and statistics")
	fmt.Println("  ips blocked                         List all blocked IPs")
	fmt.Println("  ips whitelist                       List all whitelisted IPs")
	fmt.Println("  ips unblock <ip>                    Unblock an IP address")
	fmt.Println("  ips geoip-check <ip>                Check GeoIP information for an IP")
	fmt.Println("  ips vpn-check <ip>                  Check if IP is VPN/Proxy")
	return nil
}

func (cli *CLI) handleIPSStatus(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/stats")
	if err != nil {
		return err
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(data, &stats); err != nil {
		return fmt.Errorf("parsing stats response: %w", err)
	}

	fmt.Println("IPS Status:")
	cli.printKeyValue(stats, "  ")
	return nil
}

func (cli *CLI) handleIPSBlocked(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/blocked")
	if err != nil {
		return err
	}

	var result BlockedIPsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing blocked IPs response: %w", err)
	}

	cli.printBlockedIPs(&result)
	return nil
}

func (cli *CLI) handleIPSWhitelist(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/whitelist")
	if err != nil {
		return err
	}

	var result WhitelistResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing whitelist response: %w", err)
	}

	cli.printWhitelist(&result)
	return nil
}

func (cli *CLI) handleIPSUnblock(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips unblock <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/unblock?ip=%s", url.QueryEscape(ip))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully unblocked IP: %s\n", ip)
	return nil
}

func (cli *CLI) handleGeoIPCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips geoip-check <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/geoip/check?ip=%s", url.QueryEscape(ip))

	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing GeoIP response: %w", err)
	}

	fmt.Printf("GeoIP Check for %s:\n", ip)
	cli.printKeyValue(result, "  ")
	return nil
}

func (cli *CLI) handleVPNCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips vpn-check <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/geoip/vpn-check?ip=%s", url.QueryEscape(ip))
	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing VPN check response: %w", err)
	}

	fmt.Printf("VPN/Proxy Check for %s:\n", ip)
	cli.printKeyValue(result, "  ")
	return nil
}

// Ports command handlers
func (cli *CLI) handlePorts(args []string) error {
	if len(args) == 0 {
		return cli.showPortsUsage()
	}

	portsCommands := map[string]func([]string) error{
		"list":   cli.handlePortsList,
		"add":    cli.handlePortsAdd,
		"remove": cli.handlePortsRemove,
	}

	subcommand := args[0]
	handler, exists := portsCommands[subcommand]
	if !exists {
		return fmt.Errorf("unknown ports command: %s", subcommand)
	}

	return handler(args[1:])
}

func (cli *CLI) showPortsUsage() error {
	fmt.Println("Port Management Commands:")
	fmt.Println("  ports list                                    List all configured port rules")
	fmt.Println("  ports add <port> <tcp|udp> <in|out> [action]  Add port rule")
	fmt.Println("  ports remove <port> <tcp|udp> <in|out>        Remove port rule")
	fmt.Println("\nExamples:")
	fmt.Println("  qff-cli ports add 8080 tcp in allow")
	fmt.Println("  qff-cli ports add 53 udp out allow")
	fmt.Println("  qff-cli ports add 23 tcp in deny")
	fmt.Println("  qff-cli ports remove 8080 tcp in")
	return nil
}

func (cli *CLI) handlePortsList(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ports/list")
	if err != nil {
		return err
	}

	var result PortRulesResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing port rules response: %w", err)
	}

	cli.printPortRules(&result)
	return nil
}

func (cli *CLI) handlePortsAdd(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: qff-cli ports add <port> <tcp|udp> <in|out> [action]")
	}

	port := args[0]
	protocol := args[1]
	direction := args[2]
	action := "allow"

	if len(args) > 3 {
		action = args[3]
	}

	if err := validatePortRule(port, protocol, direction, action); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ports/add?port=%s&protocol=%s&direction=%s&action=%s",
		url.QueryEscape(port), protocol, direction, action)

	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added port rule: %s/%s %s %s\n", port, protocol, direction, action)
	return nil
}

func (cli *CLI) handlePortsRemove(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: qff-cli ports remove <port> <tcp|udp> <in|out>")
	}

	port := args[0]
	protocol := args[1]
	direction := args[2]

	if err := validatePortRule(port, protocol, direction, ""); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ports/remove?port=%s&protocol=%s&direction=%s",
		url.QueryEscape(port), protocol, direction)

	_, err := cli.client.Delete(ctx, endpoint)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed port rule: %s/%s %s\n", port, protocol, direction)
	return nil
}

// Utility functions and types
func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	// Add more sophisticated IP validation here if needed
	return nil
}

func validatePortRule(port, protocol, direction, action string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number: %s", port)
	}

	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}

	if direction != "in" && direction != "out" {
		return fmt.Errorf("direction must be 'in' or 'out'")
	}

	if action != "" && action != "allow" && action != "deny" {
		return fmt.Errorf("action must be 'allow' or 'deny'")
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Response types
type StatusResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	Uptime           string `json:"uptime"`
	GeoIPAvailable   bool   `json:"geoip_available"`
	TemporaryEntries int    `json:"temporary_entries"`
}

type MetricsResponse struct {
	SystemMetrics   map[string]float64     `json:"system_metrics"`
	FirewallMetrics map[string]interface{} `json:"firewall_metrics"`
}

type BlockedIPsResponse struct {
	BlockedIPs map[string]BlockedIPDetail `json:"blocked_ips"`
}

type BlockedIPDetail struct {
	Reason    string `json:"reason"`
	BlockTime string `json:"block_time"`
}

type WhitelistResponse struct {
	WhitelistedIPs map[string]WhitelistDetail `json:"whitelisted_ips"`
}

type WhitelistDetail struct {
	Reason    string `json:"reason"`
	Permanent bool   `json:"permanent"`
	AddedTime string `json:"added_time"`
}

type PortRulesResponse struct {
	PortRules map[string]interface{} `json:"port_rules"`
}

// Print functions
func (cli *CLI) printStatus(status *StatusResponse) {
	fmt.Printf("Status: %s\n", status.Status)
	fmt.Printf("Version: %s\n", status.Version)
	fmt.Printf("Uptime: %s\n", status.Uptime)
	fmt.Printf("GeoIP Available: %t\n", status.GeoIPAvailable)
	fmt.Printf("Temporary Entries: %d\n", status.TemporaryEntries)
}

func (cli *CLI) printMetrics(metrics *MetricsResponse) {
	fmt.Println("System Metrics:")
	for key, value := range metrics.SystemMetrics {
		fmt.Printf("  %s: %.2f\n", key, value)
	}

	fmt.Println("Firewall Metrics:")
	cli.printKeyValue(metrics.FirewallMetrics, "  ")
}

func (cli *CLI) printBlockedIPs(response *BlockedIPsResponse) {
	fmt.Printf("Blocked IPs (%d):\n", len(response.BlockedIPs))
	for ip, details := range response.BlockedIPs {
		fmt.Printf("  %s: %s - %s\n", ip, details.Reason, details.BlockTime)
	}
}

func (cli *CLI) printWhitelist(response *WhitelistResponse) {
	fmt.Printf("Whitelisted IPs (%d):\n", len(response.WhitelistedIPs))
	for ip, details := range response.WhitelistedIPs {
		permanent := "temporary"
		if details.Permanent {
			permanent = "permanent"
		}
		fmt.Printf("  %s: %s (%s) - %s\n", ip, details.Reason, permanent, details.AddedTime)
	}
}

func (cli *CLI) printPortRules(response *PortRulesResponse) {
	fmt.Println("Current Port Rules:")
	cli.printKeyValue(response.PortRules, "  ")
}

func (cli *CLI) printIPList(listType string, result map[string]interface{}) {
	fmt.Printf("%s entries:\n", strings.Title(listType))
	cli.printKeyValue(result, "  ")
}

func (cli *CLI) printKeyValue(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			cli.printKeyValue(v, indent+"  ")
		case []interface{}:
			fmt.Printf("%s%s: [%d items]\n", indent, key, len(v))
			for i, item := range v {
				fmt.Printf("%s  [%d]: %v\n", indent, i, item)
			}
		case float64:
			fmt.Printf("%s%s: %.2f\n", indent, key, v)
		default:
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}