// internal/logger/logger.go
package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"
)

type Logger struct {
	slog       *slog.Logger
	level      *slog.LevelVar
	prometheus *PrometheusLogger
}

type PrometheusLogger struct {
	logCounter *prometheus.CounterVec
}

var DefaultLogger *Logger

func init() {
	DefaultLogger = New()
}

func New() *Logger {
	// levelVar allows us to change the log level dynamically.
	levelVar := new(slog.LevelVar)
	levelVar.Set(slog.LevelInfo) // Default to Info level

	promLogger := &PrometheusLogger{
		logCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "qff_log_entries_total",
				Help: "Total number of log entries by level",
			},
			[]string{"level", "component"},
		),
	}

	// It's safe to ignore this error if the metric is already registered
	_ = prometheus.Register(promLogger.logCounter)

	// Use a JSON handler for structured logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelVar})

	return &Logger{
		slog:       slog.New(handler),
		level:      levelVar,
		prometheus: promLogger,
	}
}

// SetLevel dynamically changes the logger's minimum level.
func (l *Logger) SetLevel(level string) {
	switch level {
	case "debug":
		l.level.Set(slog.LevelDebug)
	case "info":
		l.level.Set(slog.LevelInfo)
	case "warn":
		l.level.Set(slog.LevelWarn)
	case "error":
		l.level.Set(slog.LevelError)
	default:
		l.level.Set(slog.LevelInfo) // Default to info
	}
	l.Info("logger", "Log level set", "level", l.level.Level().String())
}

func (l *Logger) log(ctx context.Context, level slog.Level, component, msg string, fields ...interface{}) {
	// Prometheus metrics
	l.prometheus.logCounter.WithLabelValues(level.String(), component).Inc()

	// Add the component as a structured field and log
	args := append([]interface{}{"component", component}, fields...)
	l.slog.Log(ctx, level, msg, args...)
}

func (l *Logger) Info(component, msg string, fields ...interface{}) {
	l.log(context.Background(), slog.LevelInfo, component, msg, fields...)
}

func (l *Logger) Error(component, msg string, fields ...interface{}) {
	l.log(context.Background(), slog.LevelError, component, msg, fields...)
}

func (l *Logger) Debug(component, msg string, fields ...interface{}) {
	l.log(context.Background(), slog.LevelDebug, component, msg, fields...)
}

func (l *Logger) Warn(component, msg string, fields ...interface{}) {
	l.log(context.Background(), slog.LevelWarn, component, msg, fields...)
}

// Global logging functions
func Info(component, msg string, fields ...interface{}) {
	DefaultLogger.Info(component, msg, fields...)
}

func Error(component, msg string, fields ...interface{}) {
	DefaultLogger.Error(component, msg, fields...)
}

func Debug(component, msg string, fields ...interface{}) {
	DefaultLogger.Debug(component, msg, fields...)
}

func Warn(component, msg string, fields ...interface{}) {
	DefaultLogger.Warn(component, msg, fields...)
}

func SetLevel(level string) {
	DefaultLogger.SetLevel(level)
}
