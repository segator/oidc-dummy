VERSION 0.6

deps:
    FROM golang:1.20
    WORKDIR /src
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE IMAGE --cache-hint

build:
    FROM +deps
    COPY . .
    # -ldflags '-w -extldflags "-static"' to ensure the binary is static
    RUN CGO_ENABLED=0 go build -ldflags '-w -extldflags "-static"' -o /app
    SAVE ARTIFACT /app AS LOCAL build/


docker:
    FROM alpine
    ENV CLIENT_ID=""
    ENV CLIENT_SECRET=""
    ENV REDIRECT_URL="http://localhost:9999/callback"
    ENV ISSUER_URL=""
    ENV SCOPES="openid profile"
    EXPOSE 9999
    COPY +build/app /
    ENTRYPOINT ["/app"]
    CMD "serve"
    SAVE IMAGE --push segator/oidc-dummy:latest
