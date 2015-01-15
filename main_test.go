package main

import (
	"fmt"
	"github.com/dougjohnson/authproxy/handlers"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"code.google.com/p/gcfg"
)

type scenario struct {
	identity_required  bool
	whitelisted        bool
	incomplete_profile bool
	missing_from_org   bool
	expected_status    int
	expected_body      string
}

var (
	proxyPort int = 9060
)

const github_user_full_profile_json = `{"login":"test_user","name":"Test User","email":"test_user@test.com"}`

const github_user_empty_profile_json = `{"login":"test_user","name":"","email":""}`

const github_org_json = `[{"login":"TestOrg"}]`

func init() {
	startDummyGitHub(github_user_empty_profile_json, 9049)
	startDummyGitHub(github_user_full_profile_json, 9050)
	startDummyBackend()
}

func TestScenario1(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        false,
		incomplete_profile: false,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[Test User]",
	}
	s.test(t)
}

func TestScenario2(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        false,
		incomplete_profile: true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please edit your GitHub profile and add your Name and Email first.",
	}
	s.test(t)
}

func TestScenario3(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        true,
		incomplete_profile: true,
		missing_from_org:   false,
		expected_status:    401,
		expected_body:      "Not Authorized. Please edit your GitHub profile and add your Name and Email first.",
	}
	s.test(t)
}

func TestScenario4(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        true,
		incomplete_profile: false,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[Test User]",
	}
	s.test(t)
}

func TestScenario5(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        false,
		incomplete_profile: false,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[Test User]",
	}
	s.test(t)
}

func TestScenario6(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        true,
		incomplete_profile: false,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[]",
	}
	s.test(t)
}

func TestScenario7(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        false,
		incomplete_profile: true,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[]",
	}
	s.test(t)
}

func TestScenario8(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        true,
		incomplete_profile: true,
		missing_from_org:   false,
		expected_status:    200,
		expected_body:      "[]",
	}
	s.test(t)
}

func TestScenario9(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        false,
		incomplete_profile: false,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario10(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        false,
		incomplete_profile: true,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario11(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        true,
		incomplete_profile: true,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario12(t *testing.T) {
	s := scenario{
		identity_required:  true,
		whitelisted:        true,
		incomplete_profile: false,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario13(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        false,
		incomplete_profile: false,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario14(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        true,
		incomplete_profile: false,
		missing_from_org:   true,
		expected_status:    200,
		expected_body:      "[]",
	}
	s.test(t)
}

func TestScenario15(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        false,
		incomplete_profile: true,
		missing_from_org:   true,
		expected_status:    401,
		expected_body:      "Not Authorized. Please check with your local GitHub owner that you are added to the correct Organization.",
	}
	s.test(t)
}

func TestScenario16(t *testing.T) {
	s := scenario{
		identity_required:  false,
		whitelisted:        true,
		incomplete_profile: true,
		missing_from_org:   true,
		expected_status:    200,
		expected_body:      "[]",
	}
	s.test(t)
}

func startDummyGitHub(user_json string, port int) {
	log.Printf("Starting Dummy GitHub on port %d...", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirect_uri := r.FormValue("redirect_uri")
		log.Println(redirect_uri)
		state := r.FormValue("state")
		http.Redirect(w, r, redirect_uri+"?code=test_code&state="+state, http.StatusFound)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "test_code" {
			http.Error(w, "Invalid Code", 400)
			return
		}
		if r.FormValue("client_id") == "" {
			http.Error(w, "Missing client_id", 400)
			return
		}
		if r.FormValue("client_secret") == "" {
			http.Error(w, "Missing client_secret", 400)
			return
		}
		if r.FormValue("redirect_uri") == "" {
			http.Error(w, "Missing redirect_uri", 400)
			return
		}

		fmt.Fprint(w, "access_token=test_token")
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Authorization"][0] != "token test_token" {
			http.Error(w, "Invalid token", 401)
			return
		}

		fmt.Fprint(w, user_json)
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Authorization"][0] != "token test_token" {
			http.Error(w, "Invalid token", 401)
			return
		}

		fmt.Fprint(w, github_org_json)
	})

	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), mux)
}

func startDummyBackend() {
	log.Println("Starting BackEnd...")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header["Remote_user_full_name"])
	})
	go http.ListenAndServe("127.0.0.1:9051", mux)
}

func (s scenario) test(t *testing.T) {
	configTemplate := getConfigTemplate()
	var conf proxy.Config
	gcfg.ReadStringInto(&conf, configTemplate)
	conf.ReverseProxy[fmt.Sprintf("backend.lvh.me:%d", proxyPort)] = conf.ReverseProxy["backend.lvh.me:9000"]
	if s.identity_required == false {
		conf.ReverseProxy[fmt.Sprintf("backend.lvh.me:%d", proxyPort)].Identity_required = false
	}
	if s.whitelisted {
		conf.IPWhitelist.Ip[0] = "127.0.0.1"
	}
	if s.incomplete_profile {
		conf.GitHub.Authurl = strings.Replace(conf.GitHub.Authurl, "9050", "9049", 1)
		conf.GitHub.Tokenurl = strings.Replace(conf.GitHub.Tokenurl, "9050", "9049", 1)
		conf.GitHub.Apiurl = strings.Replace(conf.GitHub.Apiurl, "9050", "9049", 1)
	}
	if s.missing_from_org {
		conf.GitHub.Organization = "Bad Org"
	}
	conf.Server.Port = proxyPort
	conf.Server.Fqdn = fmt.Sprintf("auth.lvh.me:%d", proxyPort)

	go http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Server.Bind, conf.Server.Port), (proxy.Handlers(conf)))

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://backend.lvh.me:%d", proxyPort), nil)
	options := cookiejar.Options{}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		t.Error(err)
		return
	}
	if strings.Index(string(body[:]), s.expected_body) == -1 {
		t.Error(fmt.Sprintf("Expected >>%s<< in body. Got >>%s<<\nScenario: %+v\nConfig: %+v", s.expected_body, string(body[:]), s, conf))
	}
	if resp.StatusCode != s.expected_status {
		t.Error(fmt.Sprintf("Expected StatusCode %d. Got %d\nScenario: %+v", s.expected_status, resp.StatusCode))
	}
	proxyPort = proxyPort + 1
}

func getConfigTemplate() string {
	return `[GitHub]
authurl = http://github.lvh.me:9050/login/oauth/authorize
tokenurl = http://github.lvh.me:9050/login/oauth/access_token
apiurl = http://github.lvh.me:9050
client-id = dummy-client-id
client-secret = dummy-client-secret
scope = user:email,read:org
organization = TestOrg

[Session]
authentication-key = 0PO4hnd7wBz732wodks3118UjkdtyJlD
encryption-key = Plot85uj32hG32MDpe4yrusednlse982
max-age = 60

[Server]
bind = 127.0.0.1
port = 9000
fqdn = auth.lvh.me:9000

[ReverseProxy "backend.lvh.me:9000"]
to = http://127.0.0.1:9051
identity-required

[IPWhiteList]
ip = 127.0.1.1
`
}
