package main

import (
	"fmt"
	"github.com/dougjohnson/authproxy/handlers"
	"net/http"
)

func main() {
	conf := proxy.GetConfig()
	fmt.Printf("Proxy server started on %s:%d\n", conf.Server.Bind, conf.Server.Port)
	http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Server.Bind, conf.Server.Port), proxy.Handlers(conf))
}
