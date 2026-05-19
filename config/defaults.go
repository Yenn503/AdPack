package config

type Config struct {
	DBPath     string   `yaml:"db_path"`
	NmapArgs   []string `yaml:"nmap_args"`
	NxcPath    string   `yaml:"nxc_path"`
	BHPython   string   `yaml:"bh_python"`
	ViperOpts  ViperConfig `yaml:"viper"`
}

type ViperConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	TLS       bool   `yaml:"tls"`
}

func Default() Config {
	return Config{
		DBPath:   "",
		NmapArgs: []string{"-T4", "-sn"},
		NxcPath:  "netexec",
		BHPython: "bloodhound-python",
		ViperOpts: ViperConfig{
			Enabled: false,
			Host:    "localhost",
			Port:    7687,
		},
	}
}
