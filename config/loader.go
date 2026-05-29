package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		// Prefer adpack.yaml in current directory (auto-discover)
		if cwd, err := os.Getwd(); err == nil {
			cwdPath := filepath.Join(cwd, "adpack.yaml")
			if data, err := os.ReadFile(cwdPath); err == nil {
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					return nil, fmt.Errorf("parse %s: %w", cwdPath, err)
				}
				return &cfg, nil
			}
		}
		// Fall back to ~/.adpack/config.yaml
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".adpack", "config.yaml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Validate checks that required fields are set and tool paths exist.
func (c *Config) Validate() error {
	if c.NxcPath == "" {
		return fmt.Errorf("nxc_path is required")
	}
	if c.BHPython == "" {
		return fmt.Errorf("bh_python is required")
	}
	if c.Cracking.HashcatPath != "" {
		if _, err := exec.LookPath(c.Cracking.HashcatPath); err != nil {
			if _, err := os.Stat(c.Cracking.HashcatPath); err != nil {
				return fmt.Errorf("hashcat not found at %s — install hashcat via your OS package manager or see https://hashcat.net/hashcat/", c.Cracking.HashcatPath)
			}
		}
	}
	return nil
}
