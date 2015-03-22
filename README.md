[![Build Status](https://api.shippable.com/projects/54b81bc85ab6cc135288bf48/badge?branchName=master)](https://app.shippable.com/projects/54b81bc85ab6cc135288bf48/builds/latest)

```
                         _         _   _       ____                      
                        / \  _   _| |_| |__   |  _ \ _ __ _____  ___   _ 
                       / _ \| | | | __| '_ \  | |_) | '__/ _ \ \/ / | | |
                      / ___ \ |_| | |_| | | | |  __/| | | (_) >  <| |_| |
                     /_/   \_\__,_|\__|_| |_| |_|   |_|  \___/_/\_\\__, |
                                                                   |___/ 
```
## What is it for?
You'll find this useful if you:
* Maintain a Github Organization
* Host a number of sites that you only want to be accessible from trusted locations
* Need team members to have secure access to those sites from any location
* Would rather not worry about authentication and like the idea of GitHub powered SSO
* Might like to retrieve authenticated user details from trusted HTTP Request Headers
* Like the idea of running a single highly performant binary to secure everything

At a high level, it works like this:

```
        User @ Home                         User @ Office   
            or                                    +         
      Identity Required                           |         
            +                               (Whitelisted IP)
            |                                     |         
            |                                     |         
            |         +-----------------+         |         
            |         |                 |         |         
            +-----------+   Auth        |         |         
                      | |   Proxy     +-----------+         
                      | | +--+        | |                   
                      +-----------------+                   
                        | |  |        |                     
          +----------+  | |  |        |                     
          |          <--+ |  |        |                     
          |  GitHub  |    |  |        |                     
          |          +----+  |        |                     
          +----------+       |        |                     
                          +--+        |                     
                    GitHub Profile    |                     
                  included in headers |                     
                          |           |                     
          +-------+   +---v---+   +---v---+   +-------+     
          |       |   |       |   |       |   |       |   Sites running on ports inaccessible 
          | Site1 |   | Site2 |   | Site3 |   | Site4 |   from public internet. Only allow
          |       |   |       |   |       |   |       |   http ingress from authproxy machine.
          +-------+   +-------+   +-------+   +-------+     
```

## Get started
### Build the binary
* Install [docker](http://docker.io)

Clone this repository
```bash
git clone git@github.com:dougjohnson/authproxy.git
```
Build an authproxy docker image
```bash
cd authproxy
./init.sh
```
Run the tests
```bash
./test.sh
```
Build the binary (for 64bit linux)
```bash
./build.sh
```

### Set up DNS
All your restricted sites will be accessible via subdomains.
For the purposes of this guide, we'll assume you own the domain `laughinghyena.com` and you want all your restricted sites to be accessible under `*.internal.laughinghyena.com`. 

Set up DNS so that `*.internal.laughinghyena.com` resolves to the IP address of the box where your authproxy is running.
You can make entries in your local hosts file for testing purposes.

### Set up your config file
A sample config file is provided in this repo. Use it to create your own `authproxy.gcfg` file.
It is split into sections:

```
[GitHub]
authurl = https://github.com/login/oauth/authorize
tokenurl = https://github.com/login/oauth/access_token
apiurl = https://api.github.com
client-id = aaaaaaaaaaaaaaaaaaaaaaaa
client-secret = bbbbbbbbbbbbbbbbbbbbbbbbbb
scope = user:email,read:org
organization = Your-Github-Org
```
[Register an application](https://github.com/settings/profile) in Github under your organization and copy in the client-id and client-secret.
Use `http://auth.internal.laughinghyena.com/_callback` as the Authorization callback URL.
Set the organization to the name of your Github organization.
Everything else should be left as is.

```
[Session]
authentication-key = 32-char-long-secret-key
encryption-key = 32-char-long-secret-key
max-age = 300
```
Generate a random 32-char long key for both the above values.
Users will be transparently reauthenticated every 300 seconds.
Change this if you like.

```
[Server]
bind = 0.0.0.0
port = 80
fqdn = auth.internal.laughinghyena.com
```
Set fqdn to `auth.internal.laughinghyena.com`.
This should match the domain used in GitHub when you set up your Authorization callback URL.

```
[ReverseProxy "site1.internal.laughinghyena.com"]
to = http://127.0.0.1:81
identity-required
```
You can have as many ReverseProxy blocks as you like, one for each restricted site you want to protect.
The `to` value should be set to any url that only allows http ingress from the authproxy box.

If you want to force users to fill out some basic profile information in GitHub and to have that data passed through to your protected site in custom HTTP request headers, make sure `identity-required` is present.
All HTTP requests to your protected site will then include these HTTP headers with values which can be used to identify your user:
```
REMOTE_USER
REMOTE_USER_FULL_NAME
REMOTE_USER_EMAIL
```

```
[IPWhiteList]
ip = 95.172.74.39
ip = 95.172.74
```
A range of IP addresses can be specified by leaving off the last number of an IP address as shown.
Whitelisting an IP address means GitHub authentication is bypassed for all access from that IP.

**Note:** if the protected site has been configured with `identity-required`, access will only be permitted if the necessary values are present in the user's GitHub profile and they belong to your GitHub organization, irrespective of whether they are accessing your site from a whitelisted IP.

### Start the proxy
Make sure the `authproxy.gcfg` file is in the same location as your binary.
Start your proxy with:
```bash
cd $GOPATH/src/github.com/dougjohnson/authproxy
sudo ./authproxy
```

It will log to STDOUT, so in production you'll want to start authproxy as a daemon, directing all output to a logfile for periodic rotation:
```bash
sudo -b sh -c "setsid ./authproxy >/var/log/authproxy 2>&1 < /dev/null"
```

Make sure an http server of some sort is running at the location specified under `[ReverseProxy "site1.internal.laughinghyena.com"]` in your config file.

Visit `http://site1.internal.laughinghyena.com` and rejoice as you are authenticated via GitHub!

## HTTPS support
For HTTPS support, run your authproxy on a firewalled port behind nginx and use nginx to proxy all requests on port 80 and 443 to your authproxy.
Make sure the necessary request headers are proxied appropriately by nginx by using a nginx.conf server section like this:
```
coming soon...
```
and an authproxy.gcfg Server section like this:
```
[Server]
bind = 127.0.0.1
port = 8080
fqdn = auth.internal.laughinghyena.com
```

## Contributing
Contributions are welcome! Fork it, make your improvements, write some tests and submit a pull request.

(Kudos to the [asciiflow](http://asciiflow.com) guys for their ascii drawing tool)
