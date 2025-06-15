# Stage 1 - Build
FROM golang:1.24-bookworm AS build

# Install UPX
WORKDIR /build
RUN apt-get update && apt-get install -y xz-utils
RUN curl -sSL $(curl -s https://api.github.com/repos/upx/upx/releases/latest \
        | grep browser_download_url | grep amd64 | cut -d '"' -f 4) -o ./upx.tar.xz
RUN tar -xf ./upx.tar.xz \
    && cd upx-*-amd64_linux \
    && mv upx /bin/upx

# Build the Go part
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o papers -a -ldflags="-s -w" ./cmd/papers
RUN upx --ultra-brute -qq papers && upx -t papers

# Stage 2 - Run
FROM scratch AS runtime
COPY --from=build /build/papers ./

EXPOSE 51876
ENTRYPOINT ["./papers"]