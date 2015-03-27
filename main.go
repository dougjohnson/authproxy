package main

import (
	"fmt"
	"net/http"
  log "github.com/dougjohnson/logrus"
)

func main() {
	conf := getConfig()
  logLevel := conf.Server.LogLevel
  l, _ := log.ParseLevel(logLevel)
  log.SetLevel(l)
  log.WithFields(log.Fields{
    "ip": conf.Server.Bind,
    "port": conf.Server.Port,
  }).Info("Proxy server started")
	http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Server.Bind, conf.Server.Port), Handlers(conf))
}
