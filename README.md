# Traefik forward auth

This is a small http server that's meant to do WAF like actions on traffic forwarded from Traefik using their [forward auth mechanism](https://doc.traefik.io/traefik/middlewares/http/forwardauth/).  

To use this you will also need to create an account with MaxMind to acquire the geoip database.

The rules section is inspired by the Cloudflare rule syntax but not quite the same. Negations are supported inside the parentheses and just `and`/`or` between the expressions.

The available fields are:

| Field      | Comes from ...                                      |
| ---------- | --------------------------------------------------- |
| method     | X-Forwarded-Method                                  |
| proto      | X-Forwarded-Proto                                   |
| host       | X-Forwarded-Host                                    |
| uri        | X-Forwarded-Uri                                     |
| ip         | X-Forwarded-For                                     |
| country    | GeoIP2 Country taken from the IP in X-Forwarded-For |
| authheader | X-Custom-Auth                                       |

Available operators:

| Operator | Example                          |
| -------- | -------------------------------- |
| eq       | (authheader eq 'mysecretvalue')  |
| ne       | (host ne 'example.com)           |
| in       | (country in ['MK'])              |
| not      | (not country in ['MK'])          |
| wildcard | (path wildcard '/.well-known/*') |

The config file should look like this:

```yaml
rules:
  - name: allow well known
    priority: 1
    action: skip
    rule: "(uri wildcard '/.well-known/*')"
  - name: block outside of country
    priority: 2
    action: block
    rule: "(not country in ['MK']) and (host eq 'example.com')"

server:
  host: "127.0.0.1"
  port: 1111
  dbPath: /path/to/GeoLite2-Country.mmdb
```

If no rules match the traffic is allowed, otherwise they are run in order of priority.

## Running the server

### Podman/Docker

Run `podman build . -t traefik-forward-auth-waf` to build it.  
You can also run it as a Quadlet:

```ini
[Container]
ContainerName=traefik-forward-auth-waf
Image=localhost/traefik-forward-auth-waf-:latest
Volume=/path/to/GeoLite2-Country.mmdb:/GeoLite2-Country.mmdb
Volume=/path/to/config.yml:/config.yml

[Service]
Restart=always

[Install]
WantedBy=default.target
```

### Configuring traefik

#### Enable for an individual container

To configure your container with labels:

```yaml
- traefik.http.middlewares.traefik-forward-auth-waf.forwardauth.address=http://traefik-forward-auth-waf:1111
- traefik.http.routers.example-router.middlewares=traefik-forward-auth-waf
```

If this is running on your host and not another container, replace the URL with `http://host.containers.internal:1111` to point to the host.

Note you'll need to define the middleware in the traefik container if you want this for multiple other containers, just take the middleware definition and put it there, it's the first line.

#### Enable for an entrypoint

In your traefik config file you can enable the middleware for all routers by adding `traefik-forward-auth-waf` to the middlewares section of your router configuration:

```yml
entryPoints:
  secure:
    address: :443
    http:
      middlewares:
        - traefik-forward-auth-waf@file
```

You will also need to configure the middleware in your dynamic configuration:

```yml
# config.yml
http:
  middlewares:
    traefik-forward-auth-waf:
      forwardAuth:
        address: "http://traefik-forward-auth-waf:1111"
```

The files needs to be included as a dynamic configuration (provider) in your main configuration (it could be container labels or a file). Here is an example of a file configuration:

```yml
# traefik.yml
providers:
  docker:
    exposedbydefault: false
  file:
    filename: /etc/traefik/config.yml
    watch: true
```

## Development

To run in dev mode, install [air](https://github.com/air-verse/air) then run
`air parser.go main.go config.yml`

### Rule syntax

The rules should follow the following EBNF syntax:

```bnf
<negation> ::= "not "
<field> ::= "uri" | "host" | "ip" | "country"
<value> ::= <string> | <number>
<number> ::= "\"" [0-9]* "\""
<string> ::= "\"" ([a-z]* | [A-Z]*) "\""
<list_item> ::= <string> " "*
<list> ::= "{" <list_item>+ "}"
<comparison_operator> ::= "eq" | "ne" | "wildcard"
<set_comparison> ::= "in"
<logical_operators> ::= "and" | "or"
<simple_expr> ::= (<field> " " <comparison_operator> " " <value> | <negation>? <field> " " <set_comparison> " " <list>)
<compound_inner> ::= <simple_expr> (" " <logical_operators> " " <simple_expr>)*
<compound_expr> ::= "(" <compound_inner> ")"
<expression> ::= <simple_expr> | <compound_expr> | (<compound_expr> | <simple_expr>) " " <logical_operators> " " (<compound_expr> | <simple_expr>)
```
