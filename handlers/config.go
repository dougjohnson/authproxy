package proxy

import (
	"code.google.com/p/gcfg"
	"fmt"
)

type Config struct {
	GitHub struct {
		Authurl       string
		Tokenurl      string
		Apiurl        string
		Client_id     string
		Client_secret string
		Scope         string
		Organization  string
	}
	Session struct {
		Authentication_key string
		Encryption_key     string
		Max_age            int
	}
	Server struct {
		Bind string
		Port int
		Fqdn string
	}
	ReverseProxy map[string]*struct {
		To                []string
		Identity_required bool
	}
	IPWhitelist struct {
		Ip []string
	}
}

func GetConfig() Config {

	var config Config

	err := gcfg.ReadFileInto(&config, "authproxy.gcfg")
	if err != nil {
		fmt.Printf("Problem loading config file: %+v\n", err)
	}

	return config
}
