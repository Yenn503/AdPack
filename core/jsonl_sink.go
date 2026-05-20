package core

import (
	"encoding/json"
	"io"
	"sync"
)

// JSONLSink writes provider events as newline-delimited JSON records to an
// io.Writer. Each record embeds the full stdout and stderr payload inline,
// making it self-contained for replay and fuzz corpus consumption.
//
// Writer ownership remains with the caller; Close is not called on shutdown.
type JSONLSink struct {
	w   io.Writer
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLSink creates a sink that writes JSONL records to w. The caller
// must ensure w is safe for concurrent writes when the sink is used across
// goroutines.
func NewJSONLSink(w io.Writer) *JSONLSink {
	return &JSONLSink{
		w:   w,
		enc: json.NewEncoder(w),
	}
}

func (s *JSONLSink) Emit(ev ProviderEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Encode returns an error only when the value cannot be marshalled
	// (e.g. non-serializable types). ProviderEvent is always safe.
	_ = s.enc.Encode(ev)
}
