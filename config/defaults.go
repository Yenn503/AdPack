package config

type CrackerConfig struct {
	HashcatPath string   `yaml:"hashcat_path"`
	Wordlist    string   `yaml:"wordlist"`
	Rules       []string `yaml:"rules"`
	Timeout     int      `yaml:"timeout_seconds"`
}

type Config struct {
	DBPath    string        `yaml:"db_path"`
	NmapArgs  []string      `yaml:"nmap_args"`
	NxcPath   string        `yaml:"nxc_path"`
	BHPython  string        `yaml:"bh_python"`
	Cracking  CrackerConfig `yaml:"cracking"`
	ViperOpts ViperConfig   `yaml:"viper"`
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
	return Config{
		DBPath:   "",
		NmapArgs: []string{"-T4", "-sn"},
		NxcPath:  "netexec",
		BHPython: "bloodhound-python",
		Cracking: CrackerConfig{
			HashcatPath: "/usr/bin/hashcat",
			Wordlist:    "/usr/share/wordlists/rockyou.txt",
			Rules:       []string{"/usr/share/hashcat/rules/best64.rule"},
			Timeout:     600,
		},
		ViperOpts: ViperConfig{
			Enabled: false,
			Host:    "localhost",
			Port:    7687,
		},
	}
}
