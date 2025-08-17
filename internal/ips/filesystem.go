// internal/ips/filesystem.go
package ips

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
)

type FileSystemMonitor struct {
	config     *config.IPSConfig
	ipsManager *IPSManager
	fileHashes map[string]string
	mu         sync.RWMutex
	stopCh     chan struct{}
}

type FileChange struct {
	Path      string
	OldHash   string
	NewHash   string
	Timestamp time.Time
	Action    string // "modified", "deleted", "created"
}

func NewFileSystemMonitor(cfg *config.IPSConfig, ipsManager *IPSManager) *FileSystemMonitor {
	return &FileSystemMonitor{
		config:     cfg,
		ipsManager: ipsManager,
		fileHashes: make(map[string]string),
		stopCh:     make(chan struct{}),
	}
}

func (f *FileSystemMonitor) Start() error {
	if !f.config.EnableFileSystemMonitor {
		return nil
	}

	logger.Info("filesystem", "Starting file system monitor")

	// Set default critical files if not configured
	f.setDefaultCriticalFiles()

	// Initial scan
	f.scanFiles()

	// Start periodic monitoring
	go f.startMonitoring()

	return nil
}

func (f *FileSystemMonitor) setDefaultCriticalFiles() {
	if len(f.config.CriticalFiles) == 0 {
		f.config.CriticalFiles = []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/etc/hosts",
			"/etc/ssh/sshd_config",
			"/etc/crontab",
			"/root/.ssh/authorized_keys",
		}
	}

	if len(f.config.CriticalDirectories) == 0 {
		f.config.CriticalDirectories = []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/sbin",
		}
	}

	if f.config.FileCheckInterval == 0 {
		f.config.FileCheckInterval = 5 * time.Minute
	}
}

func (f *FileSystemMonitor) startMonitoring() {
	ticker := time.NewTicker(f.config.FileCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.checkChanges()
		case <-f.stopCh:
			return
		}
	}
}

func (f *FileSystemMonitor) scanFiles() {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Scan critical files
	for _, filePath := range f.config.CriticalFiles {
		if hash := f.calculateFileHash(filePath); hash != "" {
			f.fileHashes[filePath] = hash
		}
	}

	// Scan critical directories
	for _, dirPath := range f.config.CriticalDirectories {
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if !info.IsDir() {
				if hash := f.calculateFileHash(path); hash != "" {
					f.fileHashes[path] = hash
				}
			}
			return nil
		})
	}

	logger.Info("filesystem", "Initial file scan completed", "files", len(f.fileHashes))
}

func (f *FileSystemMonitor) checkChanges() {
	f.mu.Lock()
	defer f.mu.Unlock()

	changes := []FileChange{}

	// Check existing files
	for filePath, oldHash := range f.fileHashes {
		newHash := f.calculateFileHash(filePath)

		if newHash == "" {
			// File deleted
			changes = append(changes, FileChange{
				Path:      filePath,
				OldHash:   oldHash,
				NewHash:   "",
				Timestamp: time.Now(),
				Action:    "deleted",
			})
			delete(f.fileHashes, filePath)
		} else if newHash != oldHash {
			// File modified
			changes = append(changes, FileChange{
				Path:      filePath,
				OldHash:   oldHash,
				NewHash:   newHash,
				Timestamp: time.Now(),
				Action:    "modified",
			})
			f.fileHashes[filePath] = newHash
		}
	}

	// Check for new files in critical directories
	for _, dirPath := range f.config.CriticalDirectories {
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if !info.IsDir() {
				if _, exists := f.fileHashes[path]; !exists {
					if hash := f.calculateFileHash(path); hash != "" {
						changes = append(changes, FileChange{
							Path:      path,
							OldHash:   "",
							NewHash:   hash,
							Timestamp: time.Now(),
							Action:    "created",
						})
						f.fileHashes[path] = hash
					}
				}
			}
			return nil
		})
	}

	// Process changes
	for _, change := range changes {
		f.handleFileChange(change)
	}
}

func (f *FileSystemMonitor) calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (f *FileSystemMonitor) handleFileChange(change FileChange) {
	logger.Warn("filesystem", "Critical file change detected",
		"path", change.Path,
		"action", change.Action,
		"timestamp", change.Timestamp)

	// Send alert
	data := map[string]interface{}{
		"path":      change.Path,
		"action":    change.Action,
		"timestamp": change.Timestamp,
		"old_hash":  change.OldHash,
		"new_hash":  change.NewHash,
	}

	message := fmt.Sprintf("SECURITY: Critical file %s: %s", change.Action, change.Path)
	f.ipsManager.notifier.SendAlert(message, data)
}

func (f *FileSystemMonitor) Stop() {
	close(f.stopCh)
}

func (f *FileSystemMonitor) GetStats() map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return map[string]interface{}{
		"monitored_files": len(f.fileHashes),
		"enabled":         f.config.EnableFileSystemMonitor,
		"critical_files":  len(f.config.CriticalFiles),
		"critical_dirs":   len(f.config.CriticalDirectories),
	}
}
