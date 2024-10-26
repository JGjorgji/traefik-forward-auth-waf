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

To configure your container with labels, assuming this is running on your host and not another container add the following labels. Replace `http://host.containers.internal:1111` with the docker/podman container if you're running it there.

To configure an individual router use:

```yaml
- traefik.http.middlewares.traefik-forward-auth-waf.forwardauth.address=http://traefik-forward-auth-waf:1111
- traefik.http.routers.example-router.middlewares=traefik-forward-auth-waf
```

In your traefik config file you can enable the middleware for all routers by adding `traefik-forward-auth-waf` to the middlewares section of your router configuration:. 

Example:

```yml
entryPoints:
  secure:
    address: :443
    http:
      middlewares:
        - traefik-forward-auth-waf
```

## Development

To run in dev mode, install [air](https://github.com/air-verse/air) then run
`air parser.go main.go config.yml`

### Rule syntax

The rules should follow the following EBNF syntax:

```bnf
<expr> ::=  <negation>? "(" <negation>? <statement> ")"
<negation> ::= "not "
<field> ::= "uri" | "host" | "ip"
<value> ::= <list> | <string> | <number>
<statement> ::= <field> " " <comparison_operator> " " <value>
<string> ::= "'" ([a-z]* | [A-Z]*) "'"
<number> ::= "'" [0-9]* "'"
<list_item> ::= <string> ","?
<list> ::= "[" <list_item>+ "]"
<comparison_operator> ::= "eq" | "ne" | "in" | "wildcard"
<logical_operators> ::= "and" | "or"
<compound_single> ::= <expr> " " <logical_operators> " " <expr>
<compound> ::= <expr> (" " <logical_operators> " " <expr>)+
```
