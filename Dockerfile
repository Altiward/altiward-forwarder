# The relay: one static Go binary on distroless, running as nonroot (uid 65532).
# docker build --build-arg VERSION=0.1.0 -t altiward-forwarder .

# Base images are pinned by digest; Dependabot proposes updates.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/altiward-forwarder ./cmd/altiward-forwarder \
 && mkdir -p /out/spool

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY LICENSE NOTICE /usr/share/doc/altiward-forwarder/
COPY --from=build /out/altiward-forwarder /usr/local/bin/altiward-forwarder
# The spool: events wait here until each SIEM has accepted them. Keep it on a volume.
COPY --from=build --chown=65532:65532 /out/spool /var/lib/altiward-forwarder
VOLUME /var/lib/altiward-forwarder
EXPOSE 8443 8081
USER nonroot
HEALTHCHECK CMD ["/usr/local/bin/altiward-forwarder", "health"]
ENTRYPOINT ["/usr/local/bin/altiward-forwarder"]
