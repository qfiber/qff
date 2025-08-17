// internal/notify/notify.go
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
)

const (
	// Default configuration
	DefaultEmailTimeout   = 30 * time.Second
	DefaultWebhookTimeout = 10 * time.Second
	DefaultRetryAttempts  = 3
	DefaultRetryDelay     = 5 * time.Second
	DefaultMaxPayloadSize = 1024 * 1024 // 1MB
	DefaultRateLimit      = 100         // messages per hour

	// Alert levels
	AlertLevelInfo     = "info"
	AlertLevelWarning  = "warning"
	AlertLevelError    = "error"
	AlertLevelCritical = "critical"

	// Notification types
	NotificationTypeEmail   = "email"
	NotificationTypeWebhook = "webhook"
	NotificationTypeSlack   = "slack"
	NotificationTypeDiscord = "discord"
	NotificationTypeSMS     = "sms"
)

// Notifier handles sending notifications via multiple channels
type Notifier struct {
	config    *Config
	stats     *NotificationStats
	templates *template.Template
	client    *http.Client

	// Rate limiting
	rateLimiter *RateLimiter

	// Synchronization
	mu sync.RWMutex

	// Context for graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds notification configuration
type Config struct {
	// Global settings
	Enabled      bool          `json:"enabled"`
	DefaultLevel string        `json:"default_level"`
	RateLimit    int           `json:"rate_limit"`
	MaxRetries   int           `json:"max_retries"`
	RetryDelay   time.Duration `json:"retry_delay"`

	// Email configuration
	Email *EmailConfig `json:"email"`

	// Webhook configuration
	Webhooks []*WebhookConfig `json:"webhooks"`

	// Template configuration
	Templates *TemplateConfig `json:"templates"`

	// Security settings
	Security *SecurityConfig `json:"security"`
}

// EmailConfig holds email notification settings
type EmailConfig struct {
	Enabled            bool          `json:"enabled"`
	SMTPServer         string        `json:"smtp_server"`
	SMTPPort           int           `json:"smtp_port"`
	Username           string        `json:"username"`
	Password           string        `json:"password"`
	From               string        `json:"from"`
	To                 []string      `json:"to"`
	CC                 []string      `json:"cc,omitempty"`
	BCC                []string      `json:"bcc,omitempty"`
	UseTLS             bool          `json:"use_tls"`
	UseStartTLS        bool          `json:"use_starttls"`
	Timeout            time.Duration `json:"timeout"`
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`
	Template           string        `json:"template"`
}

// WebhookConfig holds webhook notification settings
type WebhookConfig struct {
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Timeout         time.Duration     `json:"timeout"`
	Secret          string            `json:"secret,omitempty"`
	Template        string            `json:"template"`
	RetryAttempts   int               `json:"retry_attempts"`
	MinLevel        string            `json:"min_level"`
	MaxPayloadSize  int64             `json:"max_payload_size"`
	SignatureHeader string            `json:"signature_header"`
}

// TemplateConfig holds template settings
type TemplateConfig struct {
	EmailSubject    string            `json:"email_subject"`
	EmailBody       string            `json:"email_body"`
	WebhookPayload  string            `json:"webhook_payload"`
	SlackPayload    string            `json:"slack_payload"`
	CustomTemplates map[string]string `json:"custom_templates"`
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	EnableSignatures bool     `json:"enable_signatures"`
	AllowedHosts     []string `json:"allowed_hosts"`
	MaxPayloadSize   int64    `json:"max_payload_size"`
	RequireHTTPS     bool     `json:"require_https"`
}

// NotificationStats tracks notification statistics
type NotificationStats struct {
	TotalSent      int64                    `json:"total_sent"`
	TotalFailed    int64                    `json:"total_failed"`
	EmailsSent     int64                    `json:"emails_sent"`
	EmailsFailed   int64                    `json:"emails_failed"`
	WebhooksSent   int64                    `json:"webhooks_sent"`
	WebhooksFailed int64                    `json:"webhooks_failed"`
	LastSent       time.Time                `json:"last_sent"`
	ChannelStats   map[string]*ChannelStats `json:"channel_stats"`
	RateLimited    int64                    `json:"rate_limited"`
}

// ChannelStats tracks per-channel statistics
type ChannelStats struct {
	Name           string        `json:"name"`
	Type           string        `json:"type"`
	MessagesSent   int64         `json:"messages_sent"`
	MessagesFailed int64         `json:"messages_failed"`
	LastSuccess    time.Time     `json:"last_success"`
	LastFailure    time.Time     `json:"last_failure"`
	LastError      string        `json:"last_error,omitempty"`
	AverageLatency time.Duration `json:"average_latency"`
	SuccessRate    float64       `json:"success_rate"`
}

// Alert represents a notification message
type Alert struct {
	ID        string                 `json:"id"`
	Level     string                 `json:"level"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	Priority  int                    `json:"priority"`
	Retries   int                    `json:"retries"`
}

// WebhookPayload represents the webhook payload structure
type WebhookPayload struct {
	Alert       *Alert    `json:"alert"`
	Service     string    `json:"service"`
	Version     string    `json:"version"`
	Hostname    string    `json:"hostname"`
	Environment string    `json:"environment"`
	Timestamp   time.Time `json:"timestamp"`
	Signature   string    `json:"signature,omitempty"`
}

// RateLimiter implements rate limiting for notifications
type RateLimiter struct {
	limit  int
	window time.Duration
	tokens map[string][]time.Time
	mu     sync.Mutex
}

func NewNotifier(cfg *config.NotificationConfig) *Notifier {
	ctx, cancel := context.WithCancel(context.Background())

	// Convert old config to new config format
	newConfig := convertConfig(cfg)

	// Create HTTP client with sensible defaults
	client := &http.Client{
		Timeout: DefaultWebhookTimeout,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
			MaxConnsPerHost:    5,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	// Initialize rate limiter
	rateLimiter := &RateLimiter{
		limit:  newConfig.RateLimit,
		window: time.Hour,
		tokens: make(map[string][]time.Time),
	}

	// Load templates
	templates := loadDefaultTemplates()

	return &Notifier{
		config:      newConfig,
		stats:       &NotificationStats{ChannelStats: make(map[string]*ChannelStats)},
		templates:   templates,
		client:      client,
		rateLimiter: rateLimiter,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func convertConfig(oldCfg *config.NotificationConfig) *Config {
	if oldCfg == nil {
		return getDefaultConfig()
	}

	config := &Config{
		Enabled:      true,
		DefaultLevel: AlertLevelInfo,
		RateLimit:    DefaultRateLimit,
		MaxRetries:   DefaultRetryAttempts,
		RetryDelay:   DefaultRetryDelay,
		Templates:    getDefaultTemplateConfig(),
		Security:     getDefaultSecurityConfig(),
	}

	// Convert email config
	if oldCfg.EnableEmail {
		config.Email = &EmailConfig{
			Enabled:    true,
			SMTPServer: oldCfg.EmailServer,
			SMTPPort:   oldCfg.EmailPort,
			Username:   oldCfg.EmailUser,
			Password:   oldCfg.EmailPassword,
			To:         []string{oldCfg.EmailTo},
			UseTLS:     true,
			Timeout:    DefaultEmailTimeout,
			Template:   "default_email",
		}
	}

	// Convert webhook config
	if oldCfg.EnableWebhooks && len(oldCfg.WebhookURLs) > 0 {
		config.Webhooks = make([]*WebhookConfig, len(oldCfg.WebhookURLs))
		for i, url := range oldCfg.WebhookURLs {
			config.Webhooks[i] = &WebhookConfig{
				Name:           fmt.Sprintf("webhook_%d", i+1),
				Enabled:        true,
				URL:            url,
				Method:         "POST",
				Timeout:        time.Duration(oldCfg.WebhookTimeout) * time.Second,
				RetryAttempts:  DefaultRetryAttempts,
				MinLevel:       AlertLevelInfo,
				MaxPayloadSize: DefaultMaxPayloadSize,
				Template:       "default_webhook",
			}
		}
	}

	return config
}

func getDefaultConfig() *Config {
	return &Config{
		Enabled:      false,
		DefaultLevel: AlertLevelInfo,
		RateLimit:    DefaultRateLimit,
		MaxRetries:   DefaultRetryAttempts,
		RetryDelay:   DefaultRetryDelay,
		Templates:    getDefaultTemplateConfig(),
		Security:     getDefaultSecurityConfig(),
	}
}

func getDefaultTemplateConfig() *TemplateConfig {
	return &TemplateConfig{
		EmailSubject:    "QFF Alert: {{.Alert.Title}}",
		EmailBody:       defaultEmailTemplate,
		WebhookPayload:  defaultWebhookTemplate,
		SlackPayload:    defaultSlackTemplate,
		CustomTemplates: make(map[string]string),
	}
}

func getDefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableSignatures: true,
		AllowedHosts:     []string{},
		MaxPayloadSize:   DefaultMaxPayloadSize,
		RequireHTTPS:     true,
	}
}

const defaultEmailTemplate = `
Alert Level: {{.Alert.Level | upper}}
Source: {{.Alert.Source}}
Time: {{.Alert.Timestamp.Format "2006-01-02 15:04:05 UTC"}}

Message:
{{.Alert.Message}}

{{if .Alert.Data}}
Additional Data:
{{range $key, $value := .Alert.Data}}
  {{$key}}: {{$value}}
{{end}}
{{end}}

{{if .Alert.Tags}}
Tags: {{join .Alert.Tags ", "}}
{{end}}

--
QFF Notification System
`

const defaultWebhookTemplate = `{
  "alert": {
    "id": "{{.Alert.ID}}",
    "level": "{{.Alert.Level}}",
    "title": "{{.Alert.Title}}",
    "message": "{{.Alert.Message}}",
    "source": "{{.Alert.Source}}",
    "timestamp": "{{.Alert.Timestamp.Format "2006-01-02T15:04:05Z07:00"}}",
    "priority": {{.Alert.Priority}}
    {{if .Alert.Data}},"data": {{marshal .Alert.Data}}{{end}}
    {{if .Alert.Tags}},"tags": {{marshal .Alert.Tags}}{{end}}
  },
  "service": "{{.Service}}",
  "version": "{{.Version}}",
  "hostname": "{{.Hostname}}",
  "timestamp": "{{.Timestamp.Format "2006-01-02T15:04:05Z07:00"}}"
}`

const defaultSlackTemplate = `{
  "text": "QFF Alert: {{.Alert.Title}}",
  "attachments": [
    {
      "color": "{{if eq .Alert.Level "critical"}}danger{{else if eq .Alert.Level "error"}}warning{{else}}good{{end}}",
      "fields": [
        {
          "title": "Level",
          "value": "{{.Alert.Level | upper}}",
          "short": true
        },
        {
          "title": "Source",
          "value": "{{.Alert.Source}}",
          "short": true
        },
        {
          "title": "Message",
          "value": "{{.Alert.Message}}",
          "short": false
        }
      ],
      "ts": {{.Alert.Timestamp.Unix}}
    }
  ]
}`

func loadDefaultTemplates() *template.Template {
	tmpl := template.New("notifications")

	// Add custom functions
	tmpl.Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"marshal": func(v interface{}) string {
			data, _ := json.Marshal(v)
			return string(data)
		},
	})

	// Parse default templates
	template.Must(tmpl.New("default_email").Parse(defaultEmailTemplate))
	template.Must(tmpl.New("default_webhook").Parse(defaultWebhookTemplate))
	template.Must(tmpl.New("default_slack").Parse(defaultSlackTemplate))

	return tmpl
}

// SendAlertWithDetails sends an alert through all configured notification channels
func (n *Notifier) SendAlertWithDetails(level, title, message, source string, data map[string]interface{}) error {
	if !n.config.Enabled {
		return nil
	}

	// Check rate limiting
	if !n.rateLimiter.Allow(source) {
		n.mu.Lock()
		n.stats.RateLimited++
		n.mu.Unlock()

		logger.Warn("notify", "Rate limit exceeded", "source", source)
		return fmt.Errorf("rate limit exceeded for source: %s", source)
	}

	// Create alert
	alert := &Alert{
		ID:        generateAlertID(),
		Level:     level,
		Title:     title,
		Message:   message,
		Source:    source,
		Timestamp: time.Now(),
		Data:      data,
		Priority:  getLevelPriority(level),
	}

	logger.Info("notify", "Sending alert", "level", level, "title", title, "source", source)

	// Send through all channels concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Send email if configured
	if n.config.Email != nil && n.config.Email.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.sendEmail(alert); err != nil {
				errors <- fmt.Errorf("email failed: %w", err)
			}
		}()
	}

	// Send webhooks if configured
	for _, webhook := range n.config.Webhooks {
		if webhook.Enabled && n.shouldSendToWebhook(webhook, level) {
			wg.Add(1)
			go func(wh *WebhookConfig) {
				defer wg.Done()
				if err := n.sendWebhook(alert, wh); err != nil {
					errors <- fmt.Errorf("webhook %s failed: %w", wh.Name, err)
				}
			}(webhook)
		}
	}

	// Wait for all notifications to complete
	go func() {
		wg.Wait()
		close(errors)
	}()

	// Collect any errors
	var allErrors []string
	for err := range errors {
		allErrors = append(allErrors, err.Error())
		logger.Error("notify", "Notification failed", "error", err.Error())
	}

	// Update statistics
	n.updateStats(alert, len(allErrors) == 0)

	if len(allErrors) > 0 {
		return fmt.Errorf("notification errors: %s", strings.Join(allErrors, "; "))
	}

	return nil
}

func (n *Notifier) sendEmail(alert *Alert) error {
	if n.config.Email == nil || !n.config.Email.Enabled {
		return fmt.Errorf("email not configured")
	}

	startTime := time.Now()
	channelName := "email"

	// Render email content
	subject, body, err := n.renderEmailTemplate(alert)
	if err != nil {
		n.updateChannelStats(channelName, false, time.Since(startTime), err.Error())
		return fmt.Errorf("template rendering failed: %w", err)
	}

	// Prepare email message
	message := n.buildEmailMessage(subject, body)

	// Setup SMTP authentication
	auth := smtp.PlainAuth("", n.config.Email.Username, n.config.Email.Password, n.config.Email.SMTPServer)

	// Prepare recipients
	recipients := append(n.config.Email.To, n.config.Email.CC...)
	recipients = append(recipients, n.config.Email.BCC...)

	// Send email with retry logic
	addr := fmt.Sprintf("%s:%d", n.config.Email.SMTPServer, n.config.Email.SMTPPort)

	var lastErr error
	for attempt := 1; attempt <= n.config.MaxRetries; attempt++ {
		err := smtp.SendMail(addr, auth, n.config.Email.From, recipients, []byte(message))
		if err == nil {
			n.updateChannelStats(channelName, true, time.Since(startTime), "")
			logger.Info("notify", "Email sent successfully", "recipients", len(recipients))
			return nil
		}

		lastErr = err
		if attempt < n.config.MaxRetries {
			time.Sleep(n.config.RetryDelay)
		}
	}

	n.updateChannelStats(channelName, false, time.Since(startTime), lastErr.Error())
	return fmt.Errorf("failed after %d attempts: %w", n.config.MaxRetries, lastErr)
}

func (n *Notifier) sendWebhook(alert *Alert, webhook *WebhookConfig) error {
	startTime := time.Now()
	channelName := webhook.Name

	// Render webhook payload
	payload, err := n.renderWebhookTemplate(alert, webhook)
	if err != nil {
		n.updateChannelStats(channelName, false, time.Since(startTime), err.Error())
		return fmt.Errorf("template rendering failed: %w", err)
	}

	// Validate payload size
	if int64(len(payload)) > webhook.MaxPayloadSize {
		err := fmt.Errorf("payload too large: %d bytes (max: %d)", len(payload), webhook.MaxPayloadSize)
		n.updateChannelStats(channelName, false, time.Since(startTime), err.Error())
		return err
	}

	// Send webhook with retry logic
	var lastErr error
	for attempt := 1; attempt <= webhook.RetryAttempts; attempt++ {
		err := n.sendWebhookRequest(payload, webhook)
		if err == nil {
			n.updateChannelStats(channelName, true, time.Since(startTime), "")
			logger.Info("notify", "Webhook sent successfully", "webhook", webhook.Name, "url", webhook.URL)
			return nil
		}

		lastErr = err
		if attempt < webhook.RetryAttempts {
			time.Sleep(n.config.RetryDelay)
		}
	}

	n.updateChannelStats(channelName, false, time.Since(startTime), lastErr.Error())
	return fmt.Errorf("failed after %d attempts: %w", webhook.RetryAttempts, lastErr)
}

func (n *Notifier) sendWebhookRequest(payload []byte, webhook *WebhookConfig) error {
	ctx, cancel := context.WithTimeout(n.ctx, webhook.Timeout)
	defer cancel()

	// Create request
	req, err := http.NewRequestWithContext(ctx, webhook.Method, webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "QFF-Notifier/1.0")

	// Add custom headers
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Add signature if secret is configured
	if webhook.Secret != "" {
		signature := n.generateSignature(payload, webhook.Secret)
		headerName := webhook.SignatureHeader
		if headerName == "" {
			headerName = "X-QFF-Signature"
		}
		req.Header.Set(headerName, signature)
	}

	// Send request
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (n *Notifier) renderEmailTemplate(alert *Alert) (string, string, error) {
	templateName := "default_email"
	if n.config.Email.Template != "" {
		templateName = n.config.Email.Template
	}

	data := n.buildTemplateData(alert)

	// Create function map
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"marshal": func(v interface{}) string {
			data, _ := json.Marshal(v)
			return string(data)
		},
	}

	// Render subject
	var subjectBuf bytes.Buffer
	subjectTemplate := n.config.Templates.EmailSubject
	if subjectTemplate == "" {
		subjectTemplate = "QFF Alert: {{.Alert.Title}}"
	}

	tmpl, err := template.New("subject").Funcs(funcMap).Parse(subjectTemplate)
	if err != nil {
		return "", "", fmt.Errorf("subject template parse error: %w", err)
	}

	if err := tmpl.Execute(&subjectBuf, data); err != nil {
		return "", "", fmt.Errorf("subject template execution error: %w", err)
	}

	// Render body
	var bodyBuf bytes.Buffer
	if err := n.templates.ExecuteTemplate(&bodyBuf, templateName, data); err != nil {
		return "", "", fmt.Errorf("body template execution error: %w", err)
	}

	return subjectBuf.String(), bodyBuf.String(), nil
}

func (n *Notifier) renderWebhookTemplate(alert *Alert, webhook *WebhookConfig) ([]byte, error) {
	templateName := webhook.Template
	if templateName == "" {
		templateName = "default_webhook"
	}

	data := n.buildTemplateData(alert)

	var buf bytes.Buffer
	if err := n.templates.ExecuteTemplate(&buf, templateName, data); err != nil {
		return nil, fmt.Errorf("template execution error: %w", err)
	}

	return buf.Bytes(), nil
}

func (n *Notifier) buildTemplateData(alert *Alert) map[string]interface{} {
	hostname, _ := os.Hostname()

	return map[string]interface{}{
		"Alert":       alert,
		"Service":     "QFF",
		"Version":     "1.0.0",
		"Hostname":    hostname,
		"Environment": os.Getenv("QFF_ENV"),
		"Timestamp":   time.Now(),
	}
}

func (n *Notifier) buildEmailMessage(subject, body string) string {
	headers := make(map[string]string)
	headers["From"] = n.config.Email.From
	headers["To"] = strings.Join(n.config.Email.To, ", ")
	if len(n.config.Email.CC) > 0 {
		headers["CC"] = strings.Join(n.config.Email.CC, ", ")
	}
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=\"utf-8\""
	headers["Date"] = time.Now().Format(time.RFC1123Z)

	var msg strings.Builder
	for key, value := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return msg.String()
}

func (n *Notifier) generateSignature(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (n *Notifier) shouldSendToWebhook(webhook *WebhookConfig, level string) bool {
	if webhook.MinLevel == "" {
		return true
	}

	return getLevelPriority(level) >= getLevelPriority(webhook.MinLevel)
}

func (n *Notifier) updateStats(alert *Alert, success bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.stats.TotalSent++
	if !success {
		n.stats.TotalFailed++
	}
	n.stats.LastSent = time.Now()
}

func (n *Notifier) updateChannelStats(channelName string, success bool, latency time.Duration, errorMsg string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	stats := n.stats.ChannelStats[channelName]
	if stats == nil {
		stats = &ChannelStats{
			Name: channelName,
			Type: getChannelType(channelName),
		}
		n.stats.ChannelStats[channelName] = stats
	}

	if success {
		stats.MessagesSent++
		stats.LastSuccess = time.Now()

		// Update email-specific stats
		if strings.Contains(channelName, "email") {
			n.stats.EmailsSent++
		} else {
			n.stats.WebhooksSent++
		}
	} else {
		stats.MessagesFailed++
		stats.LastFailure = time.Now()
		stats.LastError = errorMsg

		// Update email-specific stats
		if strings.Contains(channelName, "email") {
			n.stats.EmailsFailed++
		} else {
			n.stats.WebhooksFailed++
		}
	}

	// Calculate success rate
	total := stats.MessagesSent + stats.MessagesFailed
	if total > 0 {
		stats.SuccessRate = float64(stats.MessagesSent) / float64(total) * 100
	}

	// Update average latency
	if success {
		if stats.AverageLatency == 0 {
			stats.AverageLatency = latency
		} else {
			stats.AverageLatency = (stats.AverageLatency + latency) / 2
		}
	}
}

// RateLimiter methods
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Clean old tokens
	if tokens, exists := rl.tokens[key]; exists {
		var validTokens []time.Time
		for _, token := range tokens {
			if now.Sub(token) < rl.window {
				validTokens = append(validTokens, token)
			}
		}
		rl.tokens[key] = validTokens
	}

	// Check if under limit
	if len(rl.tokens[key]) >= rl.limit {
		return false
	}

	// Add new token
	rl.tokens[key] = append(rl.tokens[key], now)
	return true
}

// Utility functions
func generateAlertID() string {
	return fmt.Sprintf("qff_%d", time.Now().UnixNano())
}

func getLevelPriority(level string) int {
	switch strings.ToLower(level) {
	case AlertLevelCritical:
		return 4
	case AlertLevelError:
		return 3
	case AlertLevelWarning:
		return 2
	case AlertLevelInfo:
		return 1
	default:
		return 0
	}
}

func getChannelType(channelName string) string {
	if strings.Contains(channelName, "email") {
		return NotificationTypeEmail
	}
	if strings.Contains(channelName, "slack") {
		return NotificationTypeSlack
	}
	if strings.Contains(channelName, "discord") {
		return NotificationTypeDiscord
	}
	return NotificationTypeWebhook
}

// Public API methods
func (n *Notifier) SendInfo(title, message, source string, data map[string]interface{}) error {
	return n.SendAlertWithDetails(AlertLevelInfo, title, message, source, data)
}

func (n *Notifier) SendWarning(title, message, source string, data map[string]interface{}) error {
	return n.SendAlertWithDetails(AlertLevelWarning, title, message, source, data)
}

func (n *Notifier) SendError(title, message, source string, data map[string]interface{}) error {
	return n.SendAlertWithDetails(AlertLevelError, title, message, source, data)
}

func (n *Notifier) SendCritical(title, message, source string, data map[string]interface{}) error {
	return n.SendAlertWithDetails(AlertLevelCritical, title, message, source, data)
}

// GetStats returns current notification statistics
func (n *Notifier) GetStats() *NotificationStats {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Create a deep copy to avoid race conditions
	stats := &NotificationStats{
		TotalSent:      n.stats.TotalSent,
		TotalFailed:    n.stats.TotalFailed,
		EmailsSent:     n.stats.EmailsSent,
		EmailsFailed:   n.stats.EmailsFailed,
		WebhooksSent:   n.stats.WebhooksSent,
		WebhooksFailed: n.stats.WebhooksFailed,
		LastSent:       n.stats.LastSent,
		RateLimited:    n.stats.RateLimited,
		ChannelStats:   make(map[string]*ChannelStats),
	}

	// Deep copy channel stats
	for name, channelStats := range n.stats.ChannelStats {
		stats.ChannelStats[name] = &ChannelStats{
			Name:           channelStats.Name,
			Type:           channelStats.Type,
			MessagesSent:   channelStats.MessagesSent,
			MessagesFailed: channelStats.MessagesFailed,
			LastSuccess:    channelStats.LastSuccess,
			LastFailure:    channelStats.LastFailure,
			LastError:      channelStats.LastError,
			AverageLatency: channelStats.AverageLatency,
			SuccessRate:    channelStats.SuccessRate,
		}
	}

	return stats
}

// TestNotification sends a test notification to verify configuration
func (n *Notifier) TestNotification() error {
	data := map[string]interface{}{
		"test":      true,
		"timestamp": time.Now(),
	}

	return n.SendInfo("Test Notification", "This is a test notification from QFF", "system", data)
}

// UpdateConfig updates the notification configuration
func (n *Notifier) UpdateConfig(newConfig *Config) error {
	if newConfig == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := n.validateConfig(newConfig); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = newConfig

	// Update rate limiter
	n.rateLimiter.limit = newConfig.RateLimit

	// Update HTTP client timeout if webhooks are configured
	if len(newConfig.Webhooks) > 0 {
		maxTimeout := DefaultWebhookTimeout
		for _, webhook := range newConfig.Webhooks {
			if webhook.Timeout > maxTimeout {
				maxTimeout = webhook.Timeout
			}
		}
		n.client.Timeout = maxTimeout
	}

	logger.Info("notify", "Notification configuration updated")
	return nil
}

func (n *Notifier) validateConfig(config *Config) error {
	if config.RateLimit < 1 || config.RateLimit > 10000 {
		return fmt.Errorf("rate limit must be between 1 and 10000")
	}

	if config.MaxRetries < 1 || config.MaxRetries > 10 {
		return fmt.Errorf("max retries must be between 1 and 10")
	}

	if config.RetryDelay < time.Second || config.RetryDelay > time.Minute {
		return fmt.Errorf("retry delay must be between 1 second and 1 minute")
	}

	// Validate email config
	if config.Email != nil && config.Email.Enabled {
		if config.Email.SMTPServer == "" {
			return fmt.Errorf("email SMTP server is required")
		}
		if config.Email.From == "" {
			return fmt.Errorf("email from address is required")
		}
		if len(config.Email.To) == 0 {
			return fmt.Errorf("at least one email recipient is required")
		}
		if config.Email.SMTPPort < 1 || config.Email.SMTPPort > 65535 {
			return fmt.Errorf("email SMTP port must be between 1 and 65535")
		}
	}

	// Validate webhook configs
	for i, webhook := range config.Webhooks {
		if webhook.Enabled {
			if webhook.URL == "" {
				return fmt.Errorf("webhook %d URL is required", i)
			}

			// Validate URL
			if _, err := url.Parse(webhook.URL); err != nil {
				return fmt.Errorf("webhook %d has invalid URL: %w", i, err)
			}

			// Check HTTPS requirement
			if config.Security.RequireHTTPS && !strings.HasPrefix(webhook.URL, "https://") {
				return fmt.Errorf("webhook %d must use HTTPS", i)
			}

			if webhook.Method == "" {
				webhook.Method = "POST"
			}

			if webhook.Timeout < time.Second || webhook.Timeout > 5*time.Minute {
				return fmt.Errorf("webhook %d timeout must be between 1 second and 5 minutes", i)
			}

			if webhook.MaxPayloadSize < 1024 || webhook.MaxPayloadSize > 10*1024*1024 {
				return fmt.Errorf("webhook %d max payload size must be between 1KB and 10MB", i)
			}
		}
	}

	return nil
}

// AddTemplate adds a custom notification template
func (n *Notifier) AddTemplate(name, content string) error {
	if name == "" || content == "" {
		return fmt.Errorf("template name and content are required")
	}

	// Create function map
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"join":  strings.Join,
		"marshal": func(v interface{}) string {
			data, _ := json.Marshal(v)
			return string(data)
		},
	}

	// Parse template to validate syntax
	_, err := template.New(name).Funcs(funcMap).Parse(content)
	if err != nil {
		return fmt.Errorf("template syntax error: %w", err)
	}

	// Add to templates
	template.Must(n.templates.New(name).Parse(content))

	// Store in config
	n.mu.Lock()
	n.config.Templates.CustomTemplates[name] = content
	n.mu.Unlock()

	logger.Info("notify", "Added custom template", "name", name)
	return nil
}

// RemoveTemplate removes a custom notification template
func (n *Notifier) RemoveTemplate(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.config.Templates.CustomTemplates, name)

	// Note: We can't remove from template.Template, but we can remove from config
	logger.Info("notify", "Removed custom template", "name", name)
	return nil
}

// ListTemplates returns a list of available templates
func (n *Notifier) ListTemplates() []string {
	var templates []string

	// Add default templates
	templates = append(templates, "default_email", "default_webhook", "default_slack")

	// Add custom templates
	n.mu.RLock()
	for name := range n.config.Templates.CustomTemplates {
		templates = append(templates, name)
	}
	n.mu.RUnlock()

	sort.Strings(templates)
	return templates
}

// GetChannelHealth returns health status for all notification channels
func (n *Notifier) GetChannelHealth() map[string]bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	health := make(map[string]bool)

	for name, stats := range n.stats.ChannelStats {
		// Consider healthy if success rate > 80% and last success within 24 hours
		isHealthy := stats.SuccessRate > 80.0 &&
			time.Since(stats.LastSuccess) < 24*time.Hour
		health[name] = isHealthy
	}

	return health
}

// ResetStats resets all notification statistics
func (n *Notifier) ResetStats() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.stats = &NotificationStats{
		ChannelStats: make(map[string]*ChannelStats),
	}

	logger.Info("notify", "Notification statistics reset")
}

// IsEnabled returns whether notifications are enabled
func (n *Notifier) IsEnabled() bool {
	return n.config.Enabled
}

// GetConfigSummary returns a summary of the current configuration
func (n *Notifier) GetConfigSummary() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()

	summary := map[string]interface{}{
		"enabled":          n.config.Enabled,
		"default_level":    n.config.DefaultLevel,
		"rate_limit":       n.config.RateLimit,
		"max_retries":      n.config.MaxRetries,
		"retry_delay":      n.config.RetryDelay.String(),
		"email_enabled":    n.config.Email != nil && n.config.Email.Enabled,
		"webhook_count":    len(n.config.Webhooks),
		"custom_templates": len(n.config.Templates.CustomTemplates),
	}

	if n.config.Email != nil && n.config.Email.Enabled {
		summary["email_recipients"] = len(n.config.Email.To)
		summary["email_server"] = n.config.Email.SMTPServer
	}

	var enabledWebhooks int
	for _, webhook := range n.config.Webhooks {
		if webhook.Enabled {
			enabledWebhooks++
		}
	}
	summary["enabled_webhooks"] = enabledWebhooks

	return summary
}

// Stop gracefully shuts down the notifier
func (n *Notifier) Stop() error {
	logger.Info("notify", "Stopping notification manager")

	n.cancel()
	n.wg.Wait()

	logger.Info("notify", "Notification manager stopped")
	return nil
}

// Legacy compatibility method for backward compatibility
func (n *Notifier) SendAlert(message string, data map[string]interface{}) {
	// Extract level from message or use default
	level := n.config.DefaultLevel
	if strings.Contains(strings.ToLower(message), "critical") {
		level = AlertLevelCritical
	} else if strings.Contains(strings.ToLower(message), "error") {
		level = AlertLevelError
	} else if strings.Contains(strings.ToLower(message), "warning") {
		level = AlertLevelWarning
	}

	// Send using new interface
	err := n.SendAlertWithDetails(level, message, message, "legacy", data)
	if err != nil {
		logger.Error("notify", "Legacy alert failed", "error", err.Error())
	}
}
