package main

import (
	"net/http"
	"strings"
  "fmt"
	"time"
  "math"

  log "github.com/dougjohnson/logrus"
)

const apacheFormatPattern = "%s - - [%s] \"%s %d %d\" %.4f %s %s\n"

type authproxyLogRecord struct {
	http.ResponseWriter

	ip                                string
	time                              time.Time
	method, uri, protocol, host, user string
	status                            int
	responseBytes                     int64
	elapsedTime                       time.Duration
}

func (r *authproxyLogRecord) log() {
	requestLine := fmt.Sprintf("%s %s %s", r.method, r.uri, r.protocol)
  log.WithFields(log.Fields{
    "method": r.method,
    "uri": r.uri,
    "protocol": r.protocol,
    "ip": r.ip,
    "status": r.status,
    "responseBytes": r.responseBytes,
    "elapsedMillis": math.Floor(r.elapsedTime.Seconds()*1000 + 0.5),
    "user": r.user,
    "host": r.host,
  }).Info(requestLine)
}

func (r *authproxyLogRecord) write(p []byte) (int, error) {
	written, err := r.ResponseWriter.Write(p)
	r.responseBytes += int64(written)
	return written, err
}

func (r *authproxyLogRecord) WriteHeader(status int) {
  r.status = status
  r.ResponseWriter.WriteHeader(status)
}

type authproxyLoggingHandler struct {
	handler http.Handler
}

func (h *authproxyLoggingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth")
	username := "-"
	if u, ok := session.Values["user"]; ok {
		username = u.(user).Login
	}
	clientIP := r.RemoteAddr
	if len(r.Header.Get("X-REAL-IP")) > 0 {
		clientIP = r.Header.Get("X-REAL-IP")
	}
	if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
		clientIP = clientIP[:colon]
	}

	record := &authproxyLogRecord{
		ResponseWriter: rw,
		ip:             clientIP,
		time:           time.Time{},
		method:         r.Method,
		uri:            r.RequestURI,
		protocol:       r.Proto,
		host:           r.Host,
		user:           username,
		status:         http.StatusOK,
		elapsedTime:    time.Duration(0),
	}

	startTime := time.Now()
	h.handler.ServeHTTP(record, r)
	finishTime := time.Now()

	record.time = finishTime.UTC()
	record.elapsedTime = finishTime.Sub(startTime)

	record.log()
}
