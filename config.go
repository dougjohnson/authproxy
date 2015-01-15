package main

import (
	"code.google.com/p/gcfg"
	"log"
)

type config struct {
	GitHub struct {
		Authurl      string `gcfg:"authurl"`
		Tokenurl     string `gcfg:"tokenurl"`
		Apiurl       string `gcfg:"apiurl"`
		ClientID     string `gcfg:"client-id"`
		ClientSecret string `gcfg:"client-secret"`
		Scope        string `gcfg:"scope"`
		Organization string `gcfg:"organization"`
	}
	Session struct {
		AuthenticationKey string `gcfg:"authentication-key"`
		EncryptionKey     string `gcfg:"encryption-key"`
		MaxAge            int    `gcfg:"max-age"`
	}
	Server struct {
		Bind string `gcfg:"bind"`
		Port int    `gcfg:"port"`
		Fqdn string `gcfg:"fqdn"`
	}
	ReverseProxy map[string]*struct {
		To               []string `gcfg:"to"`
		IdentityRequired bool     `gcfg:"identity-required"`
	}
	IPWhitelist struct {
		IP []string `gcfg:"ip"`
	}
}

func getConfig() config {

	var conf config

	err := gcfg.ReadFileInto(&conf, "authproxy.gcfg")
	if err != nil {
		log.Fatalf("Problem loading config file: %+v\n", err)
	}

	return conf
}
