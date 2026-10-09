---
description: Non-HTTP TCP/UDP protocol security testing via burp-expedition (the tcp_* tools). Intercept, edit, match-and-replace, replay/fuzz, and TLS-MITM arbitrary TCP/UDP — database wire protocols (PostgreSQL/MySQL/MongoDB), Redis, MQTT/IoT, Modbus/DNP3 ICS/OT, gRPC/protobuf, or any custom binary protocol Burp's HTTP proxy cannot touch. Use when a non-HTTP service is in scope, or a plaintext protocol needs MITM/STARTTLS.
globs:
---

# Non-HTTP protocol testing (burp-expedition / tcp_* tools)

Load when: a non-HTTP TCP/UDP service is in scope, or you must intercept/rewrite
a wire protocol Burp's HTTP proxy does not handle — DB wire protocols
(PostgreSQL / MySQL / MongoDB), Redis (RESP), MQTT / IoT, Modbus-TCP / DNP3
(ICS/OT), gRPC / Protobuf, DNS, WebSocket, or a custom binary protocol.

burp-expedition is a Burp extension (Montoya) that embeds a Netty TCP/UDP/SOCKS5
proxy with TLS-MITM + STARTTLS, intercept-and-edit, match-and-replace, a replay
fuzzer, and per-message protocol dissectors. Praetor drives it over its loopback
Control API (`:18112`) through the `tcp_*` tools. Traffic does NOT go through
Burp's HTTP proxy, so evidence is the expedition connection/message id, not a
`proxy_history_index`.

## Prerequisite

The burp-expedition extension must be loaded in Burp (it starts the Control API
on `:18112`; override with `EXPEDITION_API_PORT`). `tcp_proxy_status` confirms it
is up; a down API returns a clear error with the load hint. This is a blocker,
not a skip — ask the operator to load it (Rule 32a) rather than marking the
service untested.

## Flow

1. **Listen.** `tcp_proxy_add_listener(...)` — explicit-proxy (bind port → fixed
   upstream host:port) for a known service, or a SOCKS5 listener that relays to
   each client-negotiated destination. TLS-MITM terminates client TLS with a
   per-host leaf cert; STARTTLS upgrades a plaintext→TLS negotiation
   (SMTP / IMAP / POP3 / PostgreSQL). Route the client through the listener.
2. **Capture + dissect.** `tcp_proxy_connections` lists live/closed connections;
   `tcp_proxy_messages(connection_id=)` reads the exchange. Each message is
   auto-dissected (hex/string, line/text, Redis RESP, Protobuf, DNS, MQTT,
   PostgreSQL, MySQL, MongoDB, WebSocket, Modbus/TCP, DNP3) into a decoded view —
   you see the handshake + framed messages, not just bytes.
3. **Intercept + edit.** `tcp_intercept_enable` holds live messages;
   `tcp_intercept_status` shows the queue; `tcp_intercept_forward(held_id, ...)`
   forwards (optionally edited, hex/string/decoded) or `tcp_intercept_drop`.
4. **Match-and-replace.** `tcp_match_replace_add` — literal-bytes / literal-string
   / regex rules on the raw bytes OR a dissector's decoded view (re-encoded with
   length/framing fixed); `tcp_match_replace_list` / `tcp_match_replace_remove`.
5. **Replay / fuzz.** `tcp_repeat` replays a captured payload with mutations over
   TCP/UDP — the non-HTTP analogue of Repeater/Intruder.

## What to test (per protocol)

- **DB wire (Postgres/MySQL/Mongo)**: auth handshake downgrade, cleartext creds,
  unencrypted channel, query/response tampering via match-replace.
- **Redis RESP**: unauthenticated commands, `CONFIG`/`SLAVEOF` abuse, injected
  commands via match-replace on the decoded view.
- **MQTT / IoT**: topic authz, retained-message/will abuse, injected PUBLISH.
- **Modbus/DNP3 (ICS/OT)**: unauthenticated function codes, coil/register writes
  — READ-only proof per Rule 8 (prove you could write; do not alter live state).
- **gRPC/Protobuf**: field tampering on the decoded message, trailing-data /
  framing confusion.

## Evidence

Cite the expedition **connection id + message id** (from `tcp_proxy_connections`
/ `tcp_proxy_messages`) in the finding — this lane has no `proxy_history_index`.
Keep ICS/OT and state-changing proofs benign (a read/marker, not a destructive
write), same as the web lane (Rules 5–9).
