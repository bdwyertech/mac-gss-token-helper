# gss-token-helper

A lightweight macOS-only binary that acquires SPNEGO/Negotiate tokens via the native GSS.framework (Heimdal). Designed for applications that need Kerberos proxy authentication but cannot access macOS's KCM credential cache directly (e.g. pure-Go programs).

## How it works

macOS stores Kerberos credentials in KCM (Kerberos Credential Manager), which communicates via Mach IPC. Libraries that can't use Mach IPC (like Go's `gokrb5`) can't access these credentials. This helper bridges that gap by calling GSS.framework natively and outputting the resulting SPNEGO token.

## Build

Requires macOS with Xcode Command Line Tools installed.

```bash
cargo build --release
```

The binary is at `target/release/gss-token-helper`.

## Usage

### Single-shot mode (default)

```bash
# Acquire a SPNEGO token for a service
gss-token-helper HTTP/proxy.corp.example.com

# Output: base64-encoded SPNEGO token on stdout (single line, no trailing newline)
# Errors go to stderr, exit code 1 on failure
```

### Multi-leg negotiation mode

For servers that require multiple round-trips (mutual authentication, some proxy configurations):

```bash
gss-token-helper --negotiate HTTP/proxy.corp.example.com
```

Protocol (single unversioned record format, no negotiation of versions):

1. The helper writes one record line to stdout per step.
2. The parent writes one base64-encoded server response token per line to stdin.
3. Repeats until a `COMPLETE` record is written, then the helper exits 0.

Record grammar, one line each, `<token>` base64 (standard alphabet, padded):

```
CONTINUE <token>    another leg is required; send <token> to the server
CONTINUE            same, with an empty token
COMPLETE <token>    negotiation finished; <token> is the final output token
COMPLETE            same, with no final token
```

Limits (exceeding any of these is an error, never an unbounded allocation):

| Limit | Value |
|-------|-------|
| Encoded input line, excluding newline | 65536 bytes |
| Decoded token | 49152 bytes |
| Negotiation legs | 16 |

### Delegation modes

Delegation is an explicit three-state choice; each mode requests exactly one
flag set and nothing more:

| Mode | Flags requested | How to select |
|------|-----------------|---------------|
| Disabled (default) | none | omit `--delegate` |
| Policy | `GSS_C_DELEG_POLICY_FLAG` | KDC/service policy (OK-AS-DELEGATE) |
| Required | `GSS_C_DELEG_FLAG` | `--delegate` |

Every context additionally requests mutual authentication, replay detection,
sequence detection, integrity, and confidentiality. The returned flags are
verified against what was requested, so a service that silently drops a
required property is reported as a failure instead of being ignored.

Forward your TGT to the service (requires a forwardable ticket from `kinit -f`):

```bash
gss-token-helper --delegate HTTP/proxy.corp.example.com
```

### Channel bindings (EPA)

For Windows environments with Extended Protection for Authentication, pass the TLS `tls-server-end-point` channel binding hash:

```bash
gss-token-helper --channel-bindings 0x<hex-encoded-hash> HTTP/proxy.corp.example.com
```

The hash is the SHA-256 (or appropriate algorithm) of the server's TLS certificate, as defined in RFC 5929.

### Context metadata verification

Each completed step exposes the negotiated mechanism OID (dotted form), the
returned flags, and whether another leg is required. Before a token is emitted
the returned flags are checked against the requested security properties and,
when an expected mechanism is configured, the negotiated OID is compared to it;
a mismatch is an error naming both OIDs.

### All options

```
gss-token-helper [OPTIONS] <SPN>

Options:
  -v, --version                    Print version info
  -n, --negotiate                  Multi-leg negotiation mode (stdin/stdout)
  -d, --delegate                   Request credential delegation
  -c, --channel-bindings <HEX>    TLS channel bindings hash (hex-encoded)
  -h, --help                       Print help
```

### Prerequisites

You must have a valid Kerberos ticket in your macOS credential cache. Typically this happens automatically when you log in to an Active Directory-joined Mac, or you can acquire one manually:

```bash
kinit user@REALM
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Token successfully generated and fully written to stdout |
| 1    | Failure (error message on stderr) |

Errors are reported and the exit status is chosen in exactly one place, and
stdout is written with checked writes plus a checked flush. A closed or full
stdout is therefore a failure, never a silently truncated success. Reported
categories are: usage and invalid SPN, invalid channel-binding hex, stdout or
stdin I/O failure, malformed protocol record (unknown keyword, bad base64,
oversized line or token), rejected context-state transition, GSS failure with
the underlying major/minor status text, and negotiation that exceeded the leg
limit.

## Integration

### Single-shot (Go example)

```go
cmd := exec.Command("gss-token-helper", "HTTP/proxy.example.com")
token, err := cmd.Output() // base64-encoded SPNEGO token
```

### Multi-leg negotiation (Go example)

```go
cmd := exec.Command("gss-token-helper", "--negotiate", "HTTP/proxy.example.com")
cmd.Stdin = stdinPipe
cmd.Stdout = stdoutPipe

// Read initial token
token := readLine(stdoutPipe) // base64 token

// Send to server, get response...
writeLine(stdinPipe, serverResponseBase64)

// Read next record: "CONTINUE <b64>" or "COMPLETE [<b64>]"
response := readLine(stdoutPipe)
```

Then use the token in an HTTP header:

```
Proxy-Authorization: Negotiate <token>
```

## Test strategy

| Layer | Location | Notes |
|-------|----------|-------|
| Unit and property tests | `#[cfg(test)]` modules in `src/` | `proptest`, every property ≥100 generated cases |
| Subprocess behavior | `tests/cli_output.rs` | `assert_cmd` for exact bytes and exit status |
| Compile-fail guarantees | `tests/ui.rs` + `tests/ui/` | `trybuild`, gated behind the `ui-tests` feature |
| Live Kerberos / EPA | `tests/gss_macos.rs` | `#[ignore]`d, opt-in via `GSS_TEST_*` env vars |

```bash
cargo test                      # unit, property, and subprocess tests
cargo test --features ui-tests  # compile-fail tests (toolchain-sensitive)

# Opt-in live tests; require a real KDC and service principal.
GSS_TEST_SPN=HTTP/host.example.com cargo test --test gss_macos -- --ignored
```

CI runs a required macOS `quality` job (`cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test`, `cargo build`) and a separate
`ui-tests` job so toolchain-sensitive diagnostics cannot block the gate. The
toolchain is pinned in `rust-toolchain.toml`.

## License

MIT
