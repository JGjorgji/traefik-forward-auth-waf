# Traefik forward auth

This is a small http server that's meant to do WAF like actions on traffic forwarded from Traefik using their [forward auth mechanism](https://doc.traefik.io/traefik/middlewares/http/forwardauth/).  

To use this you will also need to create an account with MaxMind to acquire the geoip database.

The rules section is inspired by the Cloudflare rule syntax but not quite the same. Negations are supported inside the parentheses and just `and`/`or` between the expressions.

The available fields are:

| Field                         | Comes from ...                                      |
| ----------------------------- | --------------------------------------------------- |
| http.request.method           | X-Forwarded-Method                                  |
| proto                         | X-Forwarded-Proto                                   |
| http.host                     | X-Forwarded-Host                                    |
| http.request.uri              | X-Forwarded-Uri                                     |
| ip.src                        | X-Forwarded-For                                     |
| ip.geoip.country              | GeoIP2 Country taken from the IP in X-Forwarded-For |
| ip.geoip.continent            | GeoIP2 Continent taken from the IP in X-Forwarded-For |
| ip.geoip.asnum                | GeoIP2 ASN taken from the IP in X-Forwarded-For |
| authheader                    | X-Custom-Auth                                       |
| http.user_agent               | User-Agent                                          |
| http.request.headers["Name"]  | Access specific header by name                      |
| http.request.headers.names[0] | Access header names (first header name)            |

Available operators:

| Operator | Example                                      |
| -------- | -------------------------------------------- |
| eq       | (authheader eq 'mysecretvalue')              |
| ne       | (http.host ne 'example.com')                 |
| in       | (ip.geoip.country in {'MK'})                 |
| not      | (not ip.geoip.country in {'MK'})             |
| wildcard | (http.request.uri wildcard '/.well-known/*') |

## Header Access Examples

You can access HTTP headers using the new header access syntax:

| Example                                           | Description                          |
| ------------------------------------------------- | ------------------------------------ |
| `http.request.headers["Authorization"] eq "Bearer xyz"` | Check specific header value          |
| `http.request.headers["Content-Type"] wildcard "application/*"` | Wildcard match on header value      |
| `http.request.headers.names[0] eq "Authorization"` | Check first header name              |
| `any(http.request.headers.names[*] eq "X-Custom")` | Check if any header name matches (planned) |

The config file should look like this:

```yaml
rules:
  - name: allow well known
    priority: 1
    action: skip
    rule: "(http.request.uri wildcard '/.well-known/*')"
  - name: block outside of country
    priority: 2
    action: block
    rule: "(not ip.geoip.country in {'MK'}) and (http.host eq 'example.com')"
  - name: require auth header
    priority: 3
    action: block
    rule: "(http.request.headers[\"Authorization\"] eq \"\")"
  - name: block specific user agents
    priority: 4
    action: block
    rule: "(http.user_agent wildcard '*bot*')"

server:
  host: "127.0.0.1"
  port: 1111
  dbPath: /path/to/GeoLite2-Country.mmdb
  requireGeoIP: false  # Optional: Set to true to block requests when GeoIP fails
  logLevel: info       # Optional: debug, info, warn, error
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

**Important**: Make sure your Traefik configuration includes the `X-Forwarded-For` header. This is usually automatic, but you can ensure it's set in your dynamic configuration:

```yaml
http:
  middlewares:
    traefik-forward-auth-waf:
      forwardAuth:
        address: "http://traefik-forward-auth-waf:1111"
        trustForwardHeader: true  # Ensures X-Forwarded-For is passed
```

## Development

To run in dev mode, install [air](https://github.com/air-verse/air) then run
`air parser.go main.go config.yml`

### Rule syntax

The rules should follow the following EBNF syntax:

```bnf
<negation> ::= "not "
<field> ::= "http.request.uri" | "http.host" | "ip.src" | "ip.geoip.country" | "http.request.headers" | "http.request.headers.names" | "http.user_agent" | "authheader"
<header_access> ::= "http.request.headers[" <string> "]"
<array_access> ::= <field> "[" (<number> | "*") "]"
<field_expr> ::= <field> | <header_access> | <array_access>
<value> ::= <string> | <number>
<number> ::= "\"" [0-9]* "\""
<string> ::= "\"" ([a-z]* | [A-Z]* | [0-9]* | "-" | "_" | "." | "/" | "*")* "\""
<list_item> ::= <string> " "*
<list> ::= "{" <list_item>+ "}"
<comparison_operator> ::= "eq" | "ne" | "wildcard"
<set_comparison> ::= "in"
<logical_operators> ::= "and" | "or"
<function_call> ::= ("any" | "lower") "(" <expression> ")"
<simple_expr> ::= (<field_expr> " " <comparison_operator> " " <value> | <negation>? <field_expr> " " <set_comparison> " " <list> | <negation>? <function_call>)
<compound_inner> ::= <simple_expr> (" " <logical_operators> " " <simple_expr>)*
<compound_expr> ::= "(" <compound_inner> ")"
<expression> ::= <simple_expr> | <compound_expr> | (<compound_expr> | <simple_expr>) " " <logical_operators> " " (<compound_expr> | <simple_expr>)
```

## Troubleshooting

### "Failed to get GeoIP data" Error

If you're seeing this error, it's likely due to one of these issues:

1. **ASN Database Missing**: The GeoLite2-Country database doesn't include ASN information. If you need ASN data, download the GeoLite2-ASN database separately or set `requireGeoIP: false` in your config.

2. **Invalid IP Address**: The `X-Forwarded-For` header might contain invalid IP addresses or be missing. The `X-Forwarded-For` header is required as this service is designed to run behind a reverse proxy like Traefik.

3. **Private IP Addresses**: GeoIP databases typically don't have information for private IP addresses (192.168.x.x, 10.x.x.x, 127.x.x.x). Set `requireGeoIP: false` for development or when testing with private IPs.

4. **Missing X-Forwarded-For**: This service requires the `X-Forwarded-For` header to be set by the reverse proxy. Make sure Traefik is properly configured to forward client IP information.

5. **Database Path**: Ensure the `dbPath` in your configuration points to a valid GeoLite2 database file.

To debug GeoIP issues:

- Set `logLevel: debug` in your configuration
- Set `requireGeoIP: false` to make GeoIP optional
- Check the logs for specific error messages

Example config for development:

```yaml
server:
  host: "127.0.0.1"
  port: 1111
  dbPath: /path/to/GeoLite2-Country.mmdb
  requireGeoIP: false  # Allows requests even if GeoIP fails
  logLevel: debug      # Shows detailed error information
```
