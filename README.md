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

Protocol:
1. Writes the initial base64 token to stdout (one line)
2. Reads a base64-encoded server response token from stdin (one line)
3. Writes the next output token to stdout
4. Repeats until negotiation completes
5. Writes `OK` on completion and exits 0

### Credential delegation

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
| 0    | Token successfully generated (base64 on stdout) |
| 1    | Failure (error message on stderr) |

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

// Read next token (or "OK" if done)
response := readLine(stdoutPipe)
```

Then use the token in an HTTP header:

```
Proxy-Authorization: Negotiate <token>
```

## License

MIT
