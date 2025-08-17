// internal/geoip/geoip.go
package geoip

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"qff/internal/config"
	"qff/internal/logger"
)

type GeoIPManager struct {
	db               *geoip2.Reader
	config           *config.GeoIPConfig
	blockedCountries map[string]bool
	allowedCountries map[string]bool
	downloader       *MaxMindDownloader
}

func NewGeoIPManager(cfg *config.GeoIPConfig) *GeoIPManager {
	mgr := &GeoIPManager{
		config:           cfg,
		blockedCountries: make(map[string]bool),
		allowedCountries: make(map[string]bool),
	}

	if cfg.MaxMindAPIKey != "" {
		mgr.downloader = NewMaxMindDownloader(cfg.MaxMindAPIKey, cfg.MMDBPath)
	}

	return mgr
}

func (g *GeoIPManager) Initialize() error {
	if g.config.MMDBPath == "" {
		logger.Warn("geoip", "GeoIP database path not configured")
		return nil
	}

	// Check if database exists, download if needed
	if g.downloader != nil && g.config.AutoDownload {
		if _, err := os.Stat(g.config.MMDBPath); os.IsNotExist(err) {
			logger.Info("geoip", "Database not found, downloading")
			if err := g.downloader.DownloadDatabase(); err != nil {
				logger.Error("geoip", "Failed to download database", "error", err.Error())
			}
		}
	}

	db, err := geoip2.Open(g.config.MMDBPath)
	if err != nil {
		return err
	}
	g.db = db

	if err := g.loadCountryLists(); err != nil {
		return err
	}

	logger.Info("geoip", "GeoIP initialized", "blocked_countries", len(g.blockedCountries), "allowed_countries", len(g.allowedCountries))
	return nil
}

func (g *GeoIPManager) loadCountryLists() error {
	if g.config.CountryBlockFile != "" {
		if err := g.loadCountryFile(g.config.CountryBlockFile, g.blockedCountries); err != nil {
			return err
		}
	}

	if g.config.CountryAllowFile != "" {
		if err := g.loadCountryFile(g.config.CountryAllowFile, g.allowedCountries); err != nil {
			return err
		}
	}

	return nil
}

func (g *GeoIPManager) loadCountryFile(filename string, countryMap map[string]bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			countryMap[strings.ToUpper(line)] = true
		}
	}

	return scanner.Err()
}

func (g *GeoIPManager) IsBlocked(ip net.IP) bool {
	if g.db == nil {
		return false // If GeoIP isn't configured, we don't block.
	}

	// If both lists are empty, allow all countries.
	if len(g.allowedCountries) == 0 && len(g.blockedCountries) == 0 {
		return false
	}

	record, err := g.db.Country(ip)
	if err != nil {
		return false // Fail open if lookup fails.
	}

	country := record.Country.IsoCode

	// 1. Allow List has priority. If it's not empty, it's a strict whitelist.
	if len(g.allowedCountries) > 0 {
		return !g.allowedCountries[country] // Block if NOT in the allow list.
	}

	// 2. Block List is a fallback. If the allow list is empty, use the block list.
	return g.blockedCountries[country] // Block if IN the block list.
}

func (g *GeoIPManager) GetCountry(ip net.IP) string {
	if g.db == nil {
		return ""
	}

	record, err := g.db.Country(ip)
	if err != nil {
		return ""
	}

	return record.Country.IsoCode
}

func (g *GeoIPManager) EnableAutoDownload(apiKey string) {
	if g.downloader == nil {
		g.downloader = NewMaxMindDownloader(apiKey, g.config.MMDBPath)
	}

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if g.downloader.ShouldUpdate() {
				if err := g.downloader.DownloadDatabase(); err != nil {
					logger.Error("geoip", "Failed to auto-update database", "error", err.Error())
				}
			}
		}
	}()

	logger.Info("geoip", "Auto-download enabled for MaxMind database")
}

func (g *GeoIPManager) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}
