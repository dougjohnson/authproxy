package main

import (
	"fmt"
	"net/http"
)

func main() {
	conf := getConfig()
	fmt.Printf("Proxy server started on %s:%d\n", conf.Server.Bind, conf.Server.Port)
	http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Server.Bind, conf.Server.Port), Handlers(conf))
}
