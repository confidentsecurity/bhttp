# BHTTP - Binary HTTP Message Format

This package implements the Binary HTTP (BHTTP) message format as specified in [RFC 9292](https://www.rfc-editor.org/rfc/rfc9292.html). BHTTP is a simple binary format for representing HTTP requests and responses outside of the HTTP protocol so that they can be transformed or stored.

BHTTP is designed to convey the semantics of HTTP in an efficient way, it doesn't capture all the technical details of HTTP messages.

This package encoded/decodes `*http.Request` and `*http.Response` types to/from BHTTP.

These types don't always encode all the information required to construct a valid HTTP message. Normally a `http.Server` or `http.Transport` does some processing of these type before writing the actual HTTP messages to the wire.

For example, the `*http.Request` type has slightly different rules depending on it being used in a client-side or a server-side environment.

Similarly, this package needs to do some processing of these types before they can be encoded to a BHTTP message. The default behavior is similar to what you're used from `net/http`. See details below.

## Features

- Uses familiar `*http.Request` and `*http.Response` types.
- User-provided mapping functions for full control of the encoding/decoding behavior.
- Full implementation of RFC 9292 Binary HTTP message format including:
    - Known-Length and Indeterminate-length (streaming) messages.
    - Trailers: HTTP Headers after the body.
    - Padding: Messages can be padded so that their length is always a multiple of a specific nr.
    - Informational (1xx) responses: Not mapped by default, but can be extracted/included using custom mapping functions.

## Installation

```bash
go get github.com/confidentsecurity/bhttp
```

## Usage

### Encoding HTTP Requests

```go
import (
    "bytes"
    "github.com/confidentsecurity/bhttp"
    "net/http"
)

// Create a simple HTTP request
request, _ := http.NewRequest(http.MethodGet, "https://example.com/hello.txt", nil)
request.Header.Set("User-Agent", "custom-client/1.0")


// Encode the request to binary format
encoder := &RequestEncoder{}
msg, err := encoder.EncodeRequest(request)
if err != nil {
    // Handle error
}

// msg is an io.Reader with some additional methods to get info about the framing indicator
b, err := io.ReadAll(msg)
if err != nil {
    // Handle error
}

// b now contains all the bytes of the encoded request, but you probably want to
// write the msg itself wherever to not block on the request being finished.
```

### Decoding HTTP Requests

```go
import (
    "bytes"
    "github.com/confidentsecurity/bhttp"
    "net/http"
)

ctx := context.Background()

// Assuming you have an io.Reader from somewhere
var encodedReq io.Reader

// or if you don't, get a reader for your bytes
var encBytes []byte
encodedReq = bytes.NewReader(encBytes)

decoder := &RequestDecoder{}
decodedReq, err := decoder.DecodeRequest(ctx, encodedReq)
if err != nil {
    // Handle error
}

// decodedReq now contains the decoded HTTP request
// once you have read all of decodedReq.Body, you know the whole req has come through
```

### HTTP Responses

Encoding and decoding http.Response types work much the same

```go
import (
    "bytes"
    "github.com/confidentsecurity/bhttp"
    "net/http"
)

// Create a response
response := &http.Response{
    Status:     "OK",
    StatusCode: http.StatusOK,
    Header:     make(http.Header),
}
response.Header.Set("Content-Type", "text/plain")

// Encode the response
encoder := &ResponseEncoder{}
msg, err := encoder.EncodeResponse(res)
if err != nil {
    // Handle error
}

// The encoded message is a Reader so can be easily passed through to a decoder
decoder := &ResponseDecoder{}
ctx := context.Background()
decodedResp, err := decoder.DecodeResponse(ctx, msg)
if err != nil {
    // Handle error
}

// decoded Resp now contains an http.Response, with a Body ready for reading.
```

## Default encoding/decoding behavior

- When encoding from a `*http.Request` to BHTTP, it is interpreted as happening in a `HTTP/1.1` client-side environment.
- When decoding from BHTTP to a `*http.Request`, it is interpreted as happing in a `HTTP1/1` server-side environment.
- `*http.Response` carries no client-side or server-side distinction, it's always interpreted as a `HTTP/1.1` environment.
- `*http.Request` or `*http.Response` values that would normally result in HTTP messages with `Transfer-Encoding: chunked` will now result in indeterminate-length BHTTP messages. Note that these messages won't included any transfer-encoding, as this isn't supported by BHTTP.

## Message Format Details

The binary format follows RFC 9292 specifications and includes:

1. Framing indicator (indicates message type and length encoding)
2. Control data (method, scheme, authority, path for requests; status code for responses)
3. Header section
4. Content
5. Trailer section
6. Optional padding

### Frame Indicators

- `0`: Known-length request
- `1`: Known-length response
- `2`: Indeterminate-length request
- `3`: Indeterminate-length response

## Important Notes

1. **Header Field Names**: All header field names are automatically canonicalized according to HTTP/2 rules.

2. **Prohibited Fields**: The following pseudo-header fields are not allowed:
   - `:method`
   - `:scheme`
   - `:authority`
   - `:path`
   - `:status`

3. **Empty Values**: The package properly handles empty header values and trailers.

4. **Connection Headers**: Headers related to connection management should not be included in binary messages.

5. **Maximum Payload Size**: The default maximum payload size is 64MB. This can be modified by changing the `MaxPayloadSize` constant.

## BHTTP Limitations

- Does not support chunk extensions from HTTP/1.1
- Does not preserve HTTP/1.1 reason phrases
- Does not support header compression (HPACK/QPACK)
- CONNECT and upgrade requests, while representable, serve no practical purpose in this format

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Contributing

For guidelines on contributing to this project, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

Run tests with `go test ./...`

## References

- [RFC 9292: Binary Representation of HTTP Messages](https://www.rfc-editor.org/rfc/rfc9292.html)
- [HTTP Semantics (RFC 9110)](https://www.rfc-editor.org/rfc/rfc9110.html)
- [HTTP/2 (RFC 9113)](https://www.rfc-editor.org/rfc/rfc9113.html)
