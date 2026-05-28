package core

import (
	"math/rand"
	"time"
)

type TimingConfig struct {
	DelayMs       int     `json:"delay_ms" yaml:"delay_ms"`
	Jitter        float64 `json:"jitter" yaml:"jitter"`
	MaxConcurrent int     `json:"max_concurrent" yaml:"max_concurrent"`
}

func DefaultTiming() TimingConfig {
	return TimingConfig{
		DelayMs:       0,
		Jitter:        0.0,
		MaxConcurrent: 10,
	}
}

func (tc TimingConfig) Delay() time.Duration {
	if tc.DelayMs <= 0 {
		return 0
	}
	d := time.Duration(tc.DelayMs) * time.Millisecond
	if tc.Jitter > 0 {
		jitterMs := float64(tc.DelayMs) * tc.Jitter * (2*rand.Float64() - 1)
		d += time.Duration(jitterMs) * time.Millisecond
		if d < 0 {
			d = 0
		}
	}
	return d
}
