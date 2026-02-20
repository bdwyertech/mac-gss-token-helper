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

```bash
# Acquire a SPNEGO token for a service
gss-token-helper HTTP/proxy.corp.example.com

# Output: base64-encoded SPNEGO token on stdout (single line, no trailing newline)
# Errors go to stderr, exit code 1 on failure
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

Call from any language via process exec:

```go
cmd := exec.Command("gss-token-helper", "HTTP/proxy.example.com")
token, err := cmd.Output() // base64-encoded SPNEGO token
```

Then use the token in an HTTP header:

```
Proxy-Authorization: Negotiate <token>
```

## License

MIT
