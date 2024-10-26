FROM docker.io/library/golang:1.22-bullseye AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build

FROM scratch

COPY --from=builder /app/traefik-forward-auth-waf /traefik-forward-auth-waf

CMD [ "./traefik-forward-auth-waf", "/config.yml" ]
