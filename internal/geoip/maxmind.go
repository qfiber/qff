// internal/geoip/maxmind.go
package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"qff/internal/logger"
)

const (
	// MaxMind configuration
	MaxMindBaseURL         = "https://download.maxmind.com/app/geoip_download"
	DefaultUpdateInterval  = 7 * 24 * time.Hour // Weekly updates
	DefaultDownloadTimeout = 10 * time.Minute
	DefaultMaxFileSize     = 100 * 1024 * 1024 // 100MB max
	DefaultRetryAttempts   = 3
	DefaultRetryDelay      = 30 * time.Second

	// Database editions
	GeoLite2Country = "GeoLite2-Country"
	GeoLite2City    = "GeoLite2-City"
	GeoLite2ASN     = "GeoLite2-ASN"

	// File extensions
	TarGzSuffix = "tar.gz"
	MmdbSuffix  = ".mmdb"
)

// MaxMindDownloader handles downloading and updating MaxMind GeoIP databases
type MaxMindDownloader struct {
	// Configuration
	config *DownloaderConfig

	// State management
	mu         sync.RWMutex
	lastUpdate map[string]time.Time
	isUpdating map[string]bool

	// HTTP client
	client *http.Client
}

// DownloaderConfig holds configuration for the MaxMind downloader
type DownloaderConfig struct {
	APIKey          string        `json:"api_key"`
	DatabasePath    string        `json:"database_path"`
	UpdateInterval  time.Duration `json:"update_interval"`
	DownloadTimeout time.Duration `json:"download_timeout"`
	MaxFileSize     int64         `json:"max_file_size"`
	RetryAttempts   int           `json:"retry_attempts"`
	RetryDelay      time.Duration `json:"retry_delay"`
	EnableChecksum  bool          `json:"enable_checksum"`
	BackupOldDB     bool          `json:"backup_old_db"`
	AutoUpdate      bool          `json:"auto_update"`
}

// DatabaseInfo contains metadata about a downloaded database
type DatabaseInfo struct {
	Edition      string    `json:"edition"`
	FilePath     string    `json:"file_path"`
	Size         int64     `json:"size"`
	Checksum     string    `json:"checksum"`
	DownloadTime time.Time `json:"download_time"`
	LastUpdate   time.Time `json:"last_update"`
	Version      string    `json:"version,omitempty"`
}

// DownloadResult represents the result of a download operation
type DownloadResult struct {
	Success         bool          `json:"success"`
	DatabaseInfo    *DatabaseInfo `json:"database_info,omitempty"`
	Error           string        `json:"error,omitempty"`
	Duration        time.Duration `json:"duration"`
	BytesDownloaded int64         `json:"bytes_downloaded"`
}

func NewMaxMindDownloader(apiKeyOrConfig interface{}, dbPath ...string) *MaxMindDownloader {
	var config *DownloaderConfig

	// Handle both old and new calling conventions
	switch v := apiKeyOrConfig.(type) {
	case string:
		// Old interface: NewMaxMindDownloader(apiKey, dbPath)
		var path string
		if len(dbPath) > 0 {
			path = dbPath[0]
		}
		config = &DownloaderConfig{
			APIKey:          v,
			DatabasePath:    path,
			UpdateInterval:  DefaultUpdateInterval,
			DownloadTimeout: DefaultDownloadTimeout,
			MaxFileSize:     DefaultMaxFileSize,
			RetryAttempts:   DefaultRetryAttempts,
			RetryDelay:      DefaultRetryDelay,
			EnableChecksum:  true,
			BackupOldDB:     true,
			AutoUpdate:      true,
		}
	case *DownloaderConfig:
		// New interface: NewMaxMindDownloader(config)
		config = v
	default:
		// Fallback to default config
		config = getDefaultConfig()
	}

	// Apply defaults for missing values
	applyConfigDefaults(config)

	// Create HTTP client with timeout and reasonable defaults
	client := &http.Client{
		Timeout: config.DownloadTimeout,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
			MaxConnsPerHost:    2,
		},
	}

	return &MaxMindDownloader{
		config:     config,
		lastUpdate: make(map[string]time.Time),
		isUpdating: make(map[string]bool),
		client:     client,
	}
}

func getDefaultConfig() *DownloaderConfig {
	return &DownloaderConfig{
		UpdateInterval:  DefaultUpdateInterval,
		DownloadTimeout: DefaultDownloadTimeout,
		MaxFileSize:     DefaultMaxFileSize,
		RetryAttempts:   DefaultRetryAttempts,
		RetryDelay:      DefaultRetryDelay,
		EnableChecksum:  true,
		BackupOldDB:     true,
		AutoUpdate:      true,
	}
}

func applyConfigDefaults(config *DownloaderConfig) {
	if config.UpdateInterval == 0 {
		config.UpdateInterval = DefaultUpdateInterval
	}
	if config.DownloadTimeout == 0 {
		config.DownloadTimeout = DefaultDownloadTimeout
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = DefaultMaxFileSize
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = DefaultRetryAttempts
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = DefaultRetryDelay
	}
}

// DownloadDatabase provides the old interface - returns only error
func (m *MaxMindDownloader) DownloadDatabase() error {
	result, err := m.downloadDatabaseInternal(context.Background(), GeoLite2Country)
	if err != nil {
		return err
	}

	if result != nil && !result.Success {
		return fmt.Errorf("download failed: %s", result.Error)
	}

	return nil
}

// ShouldUpdate checks if a database should be updated (old interface)
func (m *MaxMindDownloader) ShouldUpdate() bool {
	return m.ShouldUpdateEdition(GeoLite2Country)
}

// DownloadDatabaseWithResult downloads the specified MaxMind database edition with full result
func (m *MaxMindDownloader) DownloadDatabaseWithResult(ctx context.Context, edition string) (*DownloadResult, error) {
	return m.downloadDatabaseInternal(ctx, edition)
}

// ShouldUpdateEdition checks if a specific database edition should be updated
func (m *MaxMindDownloader) ShouldUpdateEdition(edition string) bool {
	m.mu.RLock()
	lastUpdate, exists := m.lastUpdate[edition]
	m.mu.RUnlock()

	if !exists {
		return true // Never updated
	}

	return time.Since(lastUpdate) > m.config.UpdateInterval
}

// downloadDatabaseInternal is the actual implementation
func (m *MaxMindDownloader) downloadDatabaseInternal(ctx context.Context, edition string) (*DownloadResult, error) {
	if m.config.APIKey == "" {
		return nil, fmt.Errorf("MaxMind API key not configured")
	}

	if err := m.validateEdition(edition); err != nil {
		return nil, fmt.Errorf("invalid edition: %w", err)
	}

	// Check if already updating
	m.mu.Lock()
	if m.isUpdating[edition] {
		m.mu.Unlock()
		return nil, fmt.Errorf("database %s is already being updated", edition)
	}
	m.isUpdating[edition] = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.isUpdating[edition] = false
		m.mu.Unlock()
	}()

	startTime := time.Now()
	logger.Info("geoip", "Starting MaxMind database download",
		"edition", edition, "api_key_length", len(m.config.APIKey))

	result := &DownloadResult{}

	// Download with retries
	var lastErr error
	for attempt := 1; attempt <= m.config.RetryAttempts; attempt++ {
		if attempt > 1 {
			logger.Info("geoip", "Retrying download", "edition", edition, "attempt", attempt)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(m.config.RetryDelay):
			}
		}

		dbInfo, err := m.downloadWithRetry(ctx, edition)
		if err != nil {
			lastErr = err
			logger.Warn("geoip", "Download attempt failed",
				"edition", edition, "attempt", attempt, "error", err.Error())
			continue
		}

		// Success
		result.Success = true
		result.DatabaseInfo = dbInfo
		result.Duration = time.Since(startTime)
		result.BytesDownloaded = dbInfo.Size

		m.mu.Lock()
		m.lastUpdate[edition] = time.Now()
		m.mu.Unlock()

		logger.Info("geoip", "MaxMind database downloaded successfully",
			"edition", edition, "size", dbInfo.Size, "duration", result.Duration)

		return result, nil
	}

	// All attempts failed
	result.Success = false
	result.Error = fmt.Sprintf("failed after %d attempts: %v", m.config.RetryAttempts, lastErr)
	result.Duration = time.Since(startTime)

	return result, lastErr
}

func (m *MaxMindDownloader) downloadWithRetry(ctx context.Context, edition string) (*DatabaseInfo, error) {
	// Create download URL
	url := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=%s",
		MaxMindBaseURL, edition, m.config.APIKey, TarGzSuffix)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set("User-Agent", "QFF-GeoIP-Downloader/1.0")
	req.Header.Set("Accept", "application/octet-stream")

	// Make request
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download database: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("MaxMind API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Check content length
	if resp.ContentLength > m.config.MaxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", resp.ContentLength, m.config.MaxFileSize)
	}

	// Download to temporary file
	return m.downloadAndExtract(ctx, resp, edition)
}

func (m *MaxMindDownloader) downloadAndExtract(ctx context.Context, resp *http.Response, edition string) (*DatabaseInfo, error) {
	// Create temporary file
	tempFile, err := os.CreateTemp("", fmt.Sprintf("maxmind-%s-*.tar.gz", edition))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	defer func() {
		tempFile.Close()
		os.Remove(tempPath)
	}()

	// Download with progress tracking and size limit
	hasher := sha256.New()
	limitedReader := io.LimitReader(resp.Body, m.config.MaxFileSize)

	var downloadedBytes int64
	if m.config.EnableChecksum {
		// Use TeeReader for checksum calculation
		teeReader := io.TeeReader(limitedReader, hasher)
		downloadedBytes, err = io.Copy(tempFile, teeReader)
	} else {
		downloadedBytes, err = io.Copy(tempFile, limitedReader)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}

	// Verify download completed
	if resp.ContentLength > 0 && downloadedBytes != resp.ContentLength {
		return nil, fmt.Errorf("incomplete download: got %d bytes, expected %d",
			downloadedBytes, resp.ContentLength)
	}

	tempFile.Close()

	// Calculate checksum
	var checksum string
	if m.config.EnableChecksum {
		checksum = hex.EncodeToString(hasher.Sum(nil))
	}

	// Extract MMDB file
	dbInfo, err := m.extractMMDB(ctx, tempPath, edition, downloadedBytes, checksum)
	if err != nil {
		return nil, fmt.Errorf("failed to extract database: %w", err)
	}

	return dbInfo, nil
}

func (m *MaxMindDownloader) extractMMDB(ctx context.Context, tarPath, edition string, size int64, checksum string) (*DatabaseInfo, error) {
	file, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar file: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzr, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// Create tar reader
	tr := tar.NewReader(gzr)

	// Target filename to look for
	targetFile := fmt.Sprintf("%s%s", edition, MmdbSuffix)

	// Extract the MMDB file
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Check if this is the file we want
		if strings.HasSuffix(header.Name, targetFile) {
			return m.saveMMDBFile(ctx, tr, edition, header, size, checksum)
		}
	}

	return nil, fmt.Errorf("%s not found in archive", targetFile)
}

func (m *MaxMindDownloader) saveMMDBFile(ctx context.Context, tr *tar.Reader, edition string, header *tar.Header, archiveSize int64, checksum string) (*DatabaseInfo, error) {
	// Generate final path
	finalPath := m.generateDBPath(edition)

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(finalPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Backup existing file if requested
	if m.config.BackupOldDB {
		if err := m.backupExistingDB(finalPath); err != nil {
			logger.Warn("geoip", "Failed to backup existing database", "error", err.Error())
		}
	}

	// Create temporary file for atomic replacement
	tempPath := finalPath + ".tmp"
	outFile, err := os.Create(tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		outFile.Close()
		if err != nil {
			os.Remove(tempPath)
		}
	}()

	// Copy file content with context cancellation check
	written, err := m.copyWithContext(ctx, outFile, tr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract file: %w", err)
	}

	outFile.Close()

	// Atomic move
	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("failed to move file to final location: %w", err)
	}

	// Set appropriate permissions
	if err := os.Chmod(finalPath, 0644); err != nil {
		logger.Warn("geoip", "Failed to set file permissions", "path", finalPath, "error", err.Error())
	}

	// Create database info
	dbInfo := &DatabaseInfo{
		Edition:      edition,
		FilePath:     finalPath,
		Size:         written,
		Checksum:     checksum,
		DownloadTime: time.Now(),
		LastUpdate:   time.Now(),
	}

	// Try to get version from header
	if header.ModTime != (time.Time{}) {
		dbInfo.Version = header.ModTime.Format("20060102")
	}

	return dbInfo, nil
}

func (m *MaxMindDownloader) copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	var written int64

	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

func (m *MaxMindDownloader) backupExistingDB(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // No existing file to backup
	}

	backupPath := filePath + ".backup." + time.Now().Format("20060102-150405")

	return m.copyFile(filePath, backupPath)
}

func (m *MaxMindDownloader) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func (m *MaxMindDownloader) generateDBPath(edition string) string {
	if m.config.DatabasePath != "" {
		// If specific path provided, use it
		if strings.HasSuffix(m.config.DatabasePath, MmdbSuffix) {
			return m.config.DatabasePath
		}
		// Treat as directory
		return filepath.Join(m.config.DatabasePath, edition+MmdbSuffix)
	}

	// Use default path
	return filepath.Join("/var/lib/qff/geoip", edition+MmdbSuffix)
}

func (m *MaxMindDownloader) validateEdition(edition string) error {
	validEditions := []string{GeoLite2Country, GeoLite2City, GeoLite2ASN}

	for _, valid := range validEditions {
		if edition == valid {
			return nil
		}
	}

	return fmt.Errorf("unsupported edition %q, valid editions: %v", edition, validEditions)
}

// GetLastUpdate returns the last update time for a specific edition
func (m *MaxMindDownloader) GetLastUpdate(edition string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lastUpdate, exists := m.lastUpdate[edition]
	return lastUpdate, exists
}

// IsUpdating checks if a specific edition is currently being updated
func (m *MaxMindDownloader) IsUpdating(edition string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.isUpdating[edition]
}

// GetConfig returns a copy of the current configuration
func (m *MaxMindDownloader) GetConfig() *DownloaderConfig {
	configCopy := *m.config
	return &configCopy
}

// UpdateConfig updates the downloader configuration
func (m *MaxMindDownloader) UpdateConfig(newConfig *DownloaderConfig) error {
	if newConfig == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := m.validateConfig(newConfig); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	applyConfigDefaults(newConfig)
	m.config = newConfig

	// Update HTTP client timeout
	m.client.Timeout = newConfig.DownloadTimeout

	logger.Info("geoip", "MaxMind downloader configuration updated")
	return nil
}

func (m *MaxMindDownloader) validateConfig(config *DownloaderConfig) error {
	if config.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	if config.UpdateInterval < time.Hour {
		return fmt.Errorf("update interval must be at least 1 hour")
	}

	if config.DownloadTimeout < 30*time.Second {
		return fmt.Errorf("download timeout must be at least 30 seconds")
	}

	if config.MaxFileSize < 1024*1024 {
		return fmt.Errorf("max file size must be at least 1MB")
	}

	if config.RetryAttempts < 1 || config.RetryAttempts > 10 {
		return fmt.Errorf("retry attempts must be between 1 and 10")
	}

	return nil
}

// GetDatabaseInfo returns information about a downloaded database
func (m *MaxMindDownloader) GetDatabaseInfo(edition string) (*DatabaseInfo, error) {
	dbPath := m.generateDBPath(edition)

	stat, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("database %s not found", edition)
		}
		return nil, fmt.Errorf("failed to stat database file: %w", err)
	}

	m.mu.RLock()
	lastUpdate, hasUpdate := m.lastUpdate[edition]
	m.mu.RUnlock()

	dbInfo := &DatabaseInfo{
		Edition:    edition,
		FilePath:   dbPath,
		Size:       stat.Size(),
		LastUpdate: stat.ModTime(),
	}

	if hasUpdate {
		dbInfo.DownloadTime = lastUpdate
	}

	// Calculate checksum if enabled
	if m.config.EnableChecksum {
		checksum, err := m.calculateFileChecksum(dbPath)
		if err != nil {
			logger.Warn("geoip", "Failed to calculate checksum", "path", dbPath, "error", err.Error())
		} else {
			dbInfo.Checksum = checksum
		}
	}

	return dbInfo, nil
}

func (m *MaxMindDownloader) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ListAvailableEditions returns a list of supported MaxMind database editions
func (m *MaxMindDownloader) ListAvailableEditions() []string {
	return []string{GeoLite2Country, GeoLite2City, GeoLite2ASN}
}

// ForceUpdate forces an immediate update of the specified database edition
func (m *MaxMindDownloader) ForceUpdate(ctx context.Context, edition string) (*DownloadResult, error) {
	logger.Info("geoip", "Forcing database update", "edition", edition)
	return m.downloadDatabaseInternal(ctx, edition)
}
