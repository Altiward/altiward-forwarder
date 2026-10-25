# Vendored SIEM clients

This directory contains `github.com/Altiward/altiward/integrations` v0.1.0, under its
included Apache 2.0 licence. Only packages the forwarder imports and the two OCSF
contract fixtures its tests use are retained.

The Splunk client includes a local acknowledgement fix also applied to the shared
client: it requires a complete accepted HEC response and refuses redirects. This
keeps standalone relay and hook releases protected before a new shared module is
published. Docker and hook packaging explicitly build with `-mod=vendor` and disable
workspaces; `make` checks default to `GOWORK=off`.

When updating the shared module, run `GOWORK=off go mod vendor`, retain the two OCSF
fixtures from that exact module version, and confirm the new client includes this fix.
If it does not, reapply the Splunk change. Run `GOWORK=off make lint test deps-check`;
the delivery regressions must keep ambiguous batches queued. A sibling workspace
bypasses this copy, so workspace tests alone do not verify a release.
