package config

import (
	"os"

	"adpack/core"
)

type CrackerConfig struct {
	HashcatPath string   `yaml:"hashcat_path"`
	Wordlist    string   `yaml:"wordlist"`
	Rules       []string `yaml:"rules"`
	Timeout     int      `yaml:"timeout_seconds"`
}

type SeedCred struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Hash     string `yaml:"hash"`
	Domain   string `yaml:"domain"`
}

type SliverConfig struct {
	ConfigPath string `yaml:"config_path"`
	ServerAddr string `yaml:"server_addr"`
}

type Config struct {
	DBPath       string            `yaml:"db_path"`
	NmapArgs     []string          `yaml:"nmap_args"`
	NxcPath      string            `yaml:"nxc_path"`
	BHPython     string            `yaml:"bh_python"`
	ProxyAddress string            `yaml:"proxy_address"`
	Transport    string            `yaml:"transport"` // "local", "proxy", "sliver"
	Sliver       SliverConfig      `yaml:"sliver"`
	LootDir      string            `yaml:"loot_dir"`
	Cracking     CrackerConfig     `yaml:"cracking"`
	Timing       core.TimingConfig `yaml:"timing"`
	ViperOpts    ViperConfig       `yaml:"viper"`
	Scope        []string          `yaml:"scope"`
	Domain       string            `yaml:"domain"`
	Profile      string            `yaml:"profile"`
	Seeds        []SeedCred        `yaml:"seeds"`
}

type ViperConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TLS      bool   `yaml:"tls"`
}

func Default() Config {
	home, _ := os.UserHomeDir()
	defaultLoot := home + "/.adpack/loot"
	return Config{
		DBPath:       "",
		NmapArgs:     []string{"-T4", "-sn"},
		NxcPath:      "netexec",
		BHPython:     "bloodhound-python",
		ProxyAddress: "",
		Transport:    "local",
		LootDir:      defaultLoot,
		Cracking: CrackerConfig{
			HashcatPath: "/usr/bin/hashcat",
			Wordlist:    "/usr/share/wordlists/rockyou.txt",
			Rules:       []string{"/usr/share/hashcat/rules/best64.rule"},
			Timeout:     600,
		},
		Timing: core.DefaultTiming(),
		ViperOpts: ViperConfig{
			Enabled: false,
			Host:    "localhost",
			Port:    7687,
		},
	}
}
