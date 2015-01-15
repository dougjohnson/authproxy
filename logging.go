package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const apacheFormatPattern = "%s - - [%s] \"%s %d %d\" %.4f %s %s\n"

type apacheLogRecord struct {
	http.ResponseWriter

	ip                                string
	time                              time.Time
	method, uri, protocol, host, user string
	status                            int
	responseBytes                     int64
	elapsedTime                       time.Duration
}

func (r *apacheLogRecord) log(out io.Writer) {
	timeFormatted := r.time.Format("02/Jan/2006 17:04:05")
	requestLine := fmt.Sprintf("%s %s %s", r.method, r.uri, r.protocol)
	fmt.Fprintf(out, apacheFormatPattern, r.ip, timeFormatted, requestLine, r.status, r.responseBytes,
		r.elapsedTime.Seconds(), r.host, r.user)
}

func (r *apacheLogRecord) write(p []byte) (int, error) {
	written, err := r.ResponseWriter.Write(p)
	r.responseBytes += int64(written)
	return written, err
}

func (r *apacheLogRecord) writeHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

type apacheLoggingHandler struct {
	handler http.Handler
	out     io.Writer
}

func (h *apacheLoggingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth")
	username := "-"
	if u, ok := session.Values["user"]; ok {
		username = u.(user).Login
	}
	clientIP := r.RemoteAddr
	if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
		clientIP = clientIP[:colon]
	}

	record := &apacheLogRecord{
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

	record.log(h.out)
}
