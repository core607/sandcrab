# Network egress

Use `network = "none"` to disable egress, as in the installed default profile. To permit selected
destinations, use `network = { allow = ["pypi.org", "files.pythonhosted.org"] }`.
Names match exactly, case-insensitively, with an optional final dot; list each
subdomain separately. Use ASCII DNS names or encoded internationalized names.
IP literals, wildcards, URLs, ports in names and duplicate entries are refused.
There may be 1..256 entries. Callers and SDK clients cannot change this policy.

Enabled profiles receive `http_proxy`/`https_proxy` and uppercase equivalents
pointing to an HTTP CONNECT proxy, plus `all_proxy`/`ALL_PROXY` using `socks5h`.
`no_proxy`/`NO_PROXY` are empty. HTTPS clients such as Python's `urllib` use
CONNECT automatically. Plain HTTP forwarding is unsupported; select SOCKS5
with remote DNS or explicitly request a CONNECT tunnel, for example curl's
`--proxytunnel`. SOCKS5 supports domain-name CONNECT with no authentication;
IP-address requests, BIND and UDP association are refused.

Each workload has a private loopback-only network. The trusted launcher creates
its proxy listener and transfers the socket to the daemon before credential
drop and guest seccomp enforcement. It requires a positive acknowledgement;
setup failure runs no workload. No veth, external route or host DNS socket enters
the workload. Unsetting proxy variables gives no direct egress. The daemon must
itself have outbound access; a container started with `--network none` cannot
reach external destinations.

The daemon resolves allowed names through the first three literal nameservers
in `/etc/resolv.conf`, using bounded UDP queries and TCP on truncation. It uses
no search suffix, hosts-file override or NSS lookup. Recursive answers may use
CNAMEs. Local, private, metadata, multicast and special-use addresses are denied;
IPv6 destinations must be in supported global unicast space. Each connection
uses the checked numeric address, with no second name lookup. This controls the
requested destination; tunnels do not inspect TLS names, application contents
or relay behavior at an allowed remote service.

`service.max_proxy_connections` bounds the whole daemon to 1..128 concurrent
connections, default 16; each workload can hold at most eight. Handshake,
resolution and connection setup share five seconds. CONNECT headers are limited
to 8 KiB; each relay direction buffers 16 KiB, and an idle tunnel expires after
60 seconds. Capacity refusal closes the new connection. Proxy threads, buffers
and DNS work consume the daemon's resource limits. Closing, expiry, cancellation
and restart close the owned bridge and outbound connections before releasing
workload admission. Structured `networkDecision` logs record each allow/refusal
with execution ID, requested domain/port and reason, without payloads or credentials.
