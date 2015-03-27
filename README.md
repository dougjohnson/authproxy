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
* Need your team members to have secure access to those sites from any location
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

The authproxy is written in golang and needs to be compiled in order for you to deploy it.
Fortunately, through the power of [docker](http://docker.io), you can change it, compile it and run tests against it without installing golang on your machine.

You will, however need docker (which is a good thing):

1. Install [docker](http://docker.io). If on a mac or windows, use [boot2docker](http://boot2docker.io/).

2. Clone this repository
```bash
git clone git@github.com:dougjohnson/authproxy.git
```

3. Build an authproxy docker image
```bash
cd authproxy
./init.sh
```

4. Run the tests
```bash
./test.sh
```

5. Build the binary (for 64bit linux)
```bash
./build.sh
```

The above steps will create a binary which can later be deployed using ansible. Firstly though, you have some configuration to do...

### Provision yourself an Ubuntu box

This guide has been tested to work with Ubuntu 14.04. Provision a box with a public ip address in your favourite cloud provider. You'll need ssh access to that machine for ansible to work.

Restrict http ingress to your private sites / applications so that they can only be accessed from this newly provisioned box - not from the wider internet.

### Set up DNS
All your private sites will be accessible via subdomains.
For the purposes of this guide, we'll assume you own the domain `laughinghyena.com` and you want all your private sites to be accessible under `*.internal.laughinghyena.com`. 

Set up DNS so that `*.internal.laughinghyena.com` resolves to the IP address of the box where your authproxy will be running.
You can make entries in your local hosts file for testing purposes.

### Acquire a wildcard ssl certificate for your domain (eg *.internal.laughinghyena.com)
The default configuration will enforce https access to your private sites. The authproxy will offload ssl prior to proxying requests to your private sites. You'll need the wildcard certificate and the private key used to sign the certificate signing request when configuring the proxy.

### [Register an application](https://github.com/settings/profile) in Github under your organization
Make a note of the client-id and client-secret. You should set the callback_url to the ```/_callback``` path of a wildcarded subdomain, eg:

```
https://auth.internal.laughinghyena.com/_callback
```

In the above case, auth.internal.laughinghyena.com will be used later when configuring your authproxy (see fqdn)

### Configure your authproxy
All configurations are in the ansible directory. You'll need to perform the following steps

1. Edit ```ansible/inventory/hosts``` and add a line with the ip address of your newly provisioned proxy box. Include the path to the key that can be used to ssh to that box.

2. Edit ```ansible/roles/ssl-certs/vars/main.yml``` and paste in your wildcard certificate and key. *The indentation is important*.

3. Edit ```ansible/roles/authproxy/vars/main.yml```  and paste in your github details and your fqdn (eg auth.internal.laughinghyena.com)

4. Use ```ansible-vault``` to encrypt the files created in steps 2 & 3

```
ansible-vault encrypt ansible/roles/ssl-certs/vars/main.yml
ansible-vault encrypt ansible/roles/authproxy/vars/main.yml
```

5. Edit the authproxy section of ```ansible/main.yml```:

```yml
  - role: authproxy
    reverse_proxies:
    - domain: site1.internal.laughinghyena.com
      to: http://127.0.0.1:8081
    - domain: site2.internal.laughinghyena.com
      to: http://127.0.0.1:8082
    - domain: site3.internal.laughinghyena.com
      to: http://127.0.0.1:8083
      identity_required: true
    whitelisted_ips:
    - ip: 212.111.111.1
      description: office1
    - ip: 212.111.111.2
      description: office2
    - ip: 212.111.111
      description: all offices
```

Any sites that are set with ```identity_required: true``` will force authentication via GitHub irrespective of whether the request comes from a whitelisted IP.

A range of IP addresses can be specified by leaving off the last number of an IP address as shown.

All requests that have been authenticated via GitHub will have the following additional HTTP Headers added to the request for use by your downstream private site for authentication purposes  if necessary:

```
REMOTE_USER
REMOTE_USER_FULL_NAME
REMOTE_USER_EMAIL
```

### Install ansible locally:
assuming you have python installed...
```
easy_install ansible
```

### Use ansible to deploy your authproxy:

```
./deploy.sh
```

Access to any private sites listed in the config should now be restricted to members of your GitHub organization, unless they are accessing from a whitelisted IP address.

Enjoy!

## Contributing
Contributions are welcome! Fork it, make your improvements, write some tests and submit a pull request.

(Kudos to the [asciiflow](http://asciiflow.com) guys for their ascii drawing tool)
