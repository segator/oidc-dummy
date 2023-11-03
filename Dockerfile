FROM golang:1.20 AS builder
COPY . /src
WORKDIR /src
RUN  CGO_ENABLED=0 go build  -o app && ls -lah /src

FROM alpine:latest
ENV CLIENT_ID=""
ENV CLIENT_SECRET=""
ENV REDIRECT_URL="http://localhost:9999/callback"
ENV ISSUER_URL=""
ENV SCOPES="openid profile"
EXPOSE 9999
COPY --from=builder /src/app /app
ENTRYPOINT ["/app"]