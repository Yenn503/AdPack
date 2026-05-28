package utils

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Log is the package-level structured logger. It writes human-readable colored
// output to stderr by default. Call InitLogging to configure file output.
var Log = slog.New(&coloredHandler{w: os.Stderr, level: slog.LevelInfo})

var openedFiles []*os.File

// CloseLogging closes all log files opened by InitLogging.
func CloseLogging() {
	for _, f := range openedFiles {
		f.Close()
	}
	openedFiles = nil
}

// InitLogging configures the global logger. If logDir is non-empty, a JSON log
// file is created at logDir/adpack-YYYYMMDD-HHMMSS.log alongside the colored
// console handler.
func InitLogging(logDir string, verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	var writers []io.Writer
	writers = append(writers, os.Stderr)

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err == nil {
			name := fmt.Sprintf("adpack-%s.log", time.Now().Format("20060102-150405"))
			path := filepath.Join(logDir, name)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err == nil {
				writers = append(writers, f)
				openedFiles = append(openedFiles, f)
				fmt.Fprintf(os.Stderr, "  %s  %s\n",
					InfoStyle.Render("→"),
					MutedStyle.Render("Log: "+path))
			}
		}
	}

	Log = slog.New(newMultiHandler(level, writers...))
	slog.SetDefault(Log)
}

// --- Handler: colored console output ---

type coloredHandler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
	group string
}

func (h *coloredHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *coloredHandler) Handle(_ context.Context, r slog.Record) error {
	var buf strings.Builder

	// Timestamp
	buf.WriteString(DimStyle.Render(r.Time.Format("15:04:05.000")))
	buf.WriteString(" ")

	// Level badge
	switch r.Level {
	case slog.LevelDebug:
		buf.WriteString(MutedStyle.Render("[DBG]"))
	case slog.LevelInfo:
		buf.WriteString(InfoStyle.Render("[INF]"))
	case slog.LevelWarn:
		buf.WriteString(WarningStyle.Render("[WRN]"))
	case slog.LevelError:
		buf.WriteString(ErrorStyle.Render("[ERR]"))
	}
	buf.WriteString(" ")

	// Message
	buf.WriteString(r.Message)

	// Attributes
	r.Attrs(func(a slog.Attr) bool {
		buf.WriteString(" ")
		buf.WriteString(DimStyle.Render(a.Key + "="))
		buf.WriteString(ValStyle.Render(fmt.Sprint(a.Value.Any())))
		return true
	})

	// Source (debug only)
	if r.Level == slog.LevelDebug {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		if f.File != "" {
			buf.WriteString(" ")
			buf.WriteString(DimStyle.Render(fmt.Sprintf("(%s:%d)", filepath.Base(f.File), f.Line)))
		}
	}

	buf.WriteString("\n")
	_, err := io.WriteString(h.w, buf.String())
	return err
}

func (h *coloredHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &coloredHandler{w: h.w, level: h.level, attrs: append(h.attrs, attrs...), group: h.group}
}

func (h *coloredHandler) WithGroup(name string) slog.Handler {
	return &coloredHandler{w: h.w, level: h.level, attrs: h.attrs, group: name}
}

// --- Handler: multi-writer (console + file) ---

type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(level slog.Level, writers ...io.Writer) slog.Handler {
	handlers := make([]slog.Handler, 0, len(writers))
	for i, w := range writers {
		if i == 0 {
			// First writer = console (colored)
			handlers = append(handlers, &coloredHandler{w: w, level: level})
		} else {
			// Subsequent writers = JSON file output
			handlers = append(handlers, slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
		}
	}
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

// --- Convenience wrappers ---

func LogDebug(msg string, args ...any) { Log.Debug(msg, args...) }
func LogInfo(msg string, args ...any)  { Log.Info(msg, args...) }
func LogWarn(msg string, args ...any)  { Log.Warn(msg, args...) }
func LogError(msg string, args ...any) { Log.Error(msg, args...) }
