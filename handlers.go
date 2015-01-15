package main

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/justinas/alice"
)

var (
	conf    config
	proxies map[string]*httputil.ReverseProxy
	store   *sessions.CookieStore
)

type user struct {
	Login string
	Name  string
	Email string
}

type org struct {
	Login string
}

//Handlers creates a chain of middleware http handlers and
//adds them to a mux for passing into http.ListenAndServe
func Handlers(c config) *http.ServeMux {

	conf = c
	proxies = getProxies()
	store = sessions.NewCookieStore([]byte(conf.Session.AuthenticationKey), []byte(conf.Session.EncryptionKey))

	mux := http.NewServeMux()

	var r = regexp.MustCompile(`:\d*$`)
	fqdn := r.ReplaceAllString(conf.Server.Fqdn, "")

	r = regexp.MustCompile("^[^\\.]*\\.")

	store.Options = &sessions.Options{
		Domain:   r.ReplaceAllString(fqdn, ""),
		MaxAge:   conf.Session.MaxAge,
		HttpOnly: true,
	}

	// register for storing in session
	gob.Register(user{})

	//OAuth2 handlers
	oauthMiddleware := alice.New(context.ClearHandler, recoverHandler, loggingHandler)
	mux.Handle(fmt.Sprintf("%s/_login", conf.Server.Fqdn), oauthMiddleware.ThenFunc(loginHandler))
	mux.Handle(fmt.Sprintf("%s/_callback", conf.Server.Fqdn), oauthMiddleware.ThenFunc(callbackHandler))

	//Middleware to check all restricted routes
	middleware := alice.New(context.ClearHandler,
		recoverHandler,
		loggingHandler,
		targetHandler,
		whitelistHandler,
		authHandler,
		orgHandler,
		identityHandler)

	mux.Handle("/", middleware.ThenFunc(proxyHandler))

	return mux
}

// Create a SingleHostReverseProxy for each proxy target
func getProxies() map[string]*httputil.ReverseProxy {
	proxies := make(map[string]*httputil.ReverseProxy)
	for key, value := range conf.ReverseProxy {
		remote, err := url.Parse(value.To[0])
		if err != nil {
			log.Println("WARN: invalid proxy target url: " + value.To[0])
			continue
		}
		proxies[key] = httputil.NewSingleHostReverseProxy(remote)
	}
	return proxies
}

// Proxy request to the proxy target, setting the auth headers appropriately
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth")
	proxy := proxies[r.Host]
	if _, ok := session.Values["user"]; ok {
		r.Header["REMOTE_USER"] = []string{session.Values["user"].(user).Login}
		r.Header["REMOTE_USER_FULL_NAME"] = []string{session.Values["user"].(user).Name}
		r.Header["REMOTE_USER_EMAIL"] = []string{session.Values["user"].(user).Email}
	}
	proxy.ServeHTTP(w, r)
}

// Recover from any panics with a 500 instead of allowing the server to crash
func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// Log the request, apache-style
func loggingHandler(next http.Handler) http.Handler {
	return &apacheLoggingHandler{
		handler: next,
		out:     os.Stdout,
	}
}

// Check that the target host is supported
func targetHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if _, ok := proxies[r.Host]; ok {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, r.Host+" is not a supported domain", 400)
		}
	}
	return http.HandlerFunc(fn)
}

// Check if the source IP address is whitelisted. If so, jump straight to the proxyHandler
func whitelistHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr

		identityRequired := false
		for domain, value := range conf.ReverseProxy {
			if domain != r.Host {
				continue
			}
			if value.IdentityRequired {
				identityRequired = true
				break
			}
		}

		if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
			clientIP = clientIP[:colon]
		}
		for _, ip := range conf.IPWhitelist.IP {
			trimmedClientIP := clientIP
			if strings.Count(ip, ".") == 2 {
				trimmedClientIP = clientIP[:strings.LastIndex(clientIP, ".")]
			}
			if (ip == clientIP || ip == trimmedClientIP) && !identityRequired {
				proxyHandler(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// Check if the user is already authenticated
func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth")
		if _, ok := session.Values["access_token"]; ok {
			next.ServeHTTP(w, r)
		} else {
			session.Values["redirect_to"] = "http://" + r.Host + r.RequestURI
			session.Values["state"] = newState()
			session.Save(r, w)
			http.Redirect(w, r, fmt.Sprintf("http://%s/_login", conf.Server.Fqdn), http.StatusFound)
		}
	}
	return http.HandlerFunc(fn)
}

// Check if the user is in the organisation. If so, store user details in session.
func orgHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth")
		if _, ok := session.Values["user"]; ok {
			next.ServeHTTP(w, r)
		} else {
			var u user
			err := callGitHubAPI(conf.GitHub.Apiurl+"/user", session.Values["access_token"].(string), &u, false)
			if err != nil {
				http.Error(w, "Problem retrieving user info from GitHub", 500)
				return
			}

			var o []org
			err = callGitHubAPI(conf.GitHub.Apiurl+"/user/orgs", session.Values["access_token"].(string), &o, true)
			if err != nil {
				http.Error(w, "Problem retrieving org info from GitHub", 500)
				return
			}
			for _, org := range o {
				if org.Login == conf.GitHub.Organization {
					session.Values["user"] = u
					session.Save(r, w)
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.", 401)
		}
	}
	return http.HandlerFunc(fn)
}

// Check if the required identity attibutes are set (email, name, gravatar etc)
func identityHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth")
		user := session.Values["user"].(user)
		for domain, value := range conf.ReverseProxy {
			if domain != r.Host {
				continue
			}
			if !value.IdentityRequired {
				continue
			}
			if user.Name == "" || user.Email == "" {
				http.Error(w, "Not Authorized. Please edit your GitHub profile and add your Name and Email first.", 401)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// Handles redirects to /_login as a consequence of not being authenticated
func loginHandler(rw http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth")
	if _, ok := session.Values["state"]; ok {
		authURL := conf.GitHub.Authurl +
			"?client_id=" + url.QueryEscape(conf.GitHub.ClientID) +
			"&redirect_uri=" + url.QueryEscape(fmt.Sprintf("http://%s/_callback", conf.Server.Fqdn)) +
			"&scope=" + url.QueryEscape(conf.GitHub.Scope) +
			"&state=" + url.QueryEscape(session.Values["state"].(string))
		http.Redirect(rw, r, authURL, http.StatusFound)
		return
	}
	http.Error(rw, "invalid state", 400)
}

// Handles redirects to /_callback following GitHub login
// Exchanges "code" for "access token" to facilitate future API calls
func callbackHandler(rw http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth")

	defer session.Save(r, rw)
	defer delete(session.Values, "state")
	defer delete(session.Values, "redirect_to")

	if session.Values["state"] != r.FormValue("state") {
		http.Error(rw, "invalid callback", 400)
		return
	}

	if r.FormValue("code") == "" {
		http.Error(rw, "missing code in redirect from GitHub", 400)
		return
	}

	var err error
	session.Values["access_token"], err = getAccessToken(r.FormValue("code"))
	session.Save(r, rw)

	if err != nil {
		http.Error(rw, "unable to retrieve access token from GitHub: "+err.Error(), 500)
		return
	}

	http.Redirect(rw, r, session.Values["redirect_to"].(string), http.StatusFound)
}

// Exchanges Oauth2 "code" for "access token"
func getAccessToken(code string) (string, error) {
	resp, err := http.PostForm(conf.GitHub.Tokenurl, url.Values{"client_id": {conf.GitHub.ClientID}, "client_secret": {conf.GitHub.ClientSecret}, "code": {code}, "redirect_uri": {"http://" + conf.Server.Fqdn + "/_callback"}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	params, err := url.ParseQuery(string(body[:]))
	return params["access_token"][0], err
}

// Makes GitHub API call (GET only). Unmarshals the json into the struct pointed to by "target".
func callGitHubAPI(url string, token string, target interface{}, preview bool) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if preview {
		req.Header.Set("Accept", "application/vnd.github.moondragon-preview+json")
	}
	req.Header.Add("Authorization", "token "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, target)
	if err != nil {
		return err
	}
	return nil
}

// Generates a new random state for use during Oauth2 handshake
func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}
