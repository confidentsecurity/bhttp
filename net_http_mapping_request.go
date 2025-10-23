// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// RequestFromHTTP1 interprets the provided net/http request as a HTTP/1.1 request and maps
// it to a bhttp [Request].
//
// Just like net/http this method will automatically handle a few headers when appropriate:
// - Host: always set based on .Host or .URL.Host. Matches :authority request control data.
// - Content-Length: for known length requests.
//
// Note: Unless the caller explicitly sets .TransferEncoding, we don't add it.
func RequestFromHTTP1(hr *http.Request, usingProxy, serverSide bool) (*Request, error) {
	if serverSide {
		// TODO: We're currently missing support to map request control data from server side
		// requests as we don't need it for our use-case (yet?).
		return nil, fmt.Errorf("not implemented yet: %w", errors.ErrUnsupported)
	}

	contentLen, knownLen, err := determineHTTPRequestContentLength(hr, serverSide)
	if err != nil {
		return nil, fmt.Errorf("failed to map content length: %w", err)
	}

	ctrlData, header, err := mapPreBodyFromHTTP1ClientSideRequest(hr, usingProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to map pre-body: %w", err)
	}

	bdy := hr.Body
	if bdy == nil {
		bdy = http.NoBody
	}

	trailer := hr.Trailer
	// net/http automatically adds the Content-Length header for known length requests,
	// so we do the same here.
	if shouldSetContentLengthHeader(string(ctrlData.Method), knownLen, contentLen) {
		header.Set("Content-Length", strconv.Itoa(int(contentLen)))
		header.Del("Trailer")
		trailer = http.Header{}
	}

	return &Request{
		KnownLength:   knownLen,
		ContentLength: contentLen,
		ControlData:   ctrlData,
		Header:        header,
		Body:          bdy,
		Trailer:       trailer,
	}, nil
}

func shouldSetContentLengthHeader(method string, knownLen bool, contentLen int64) bool {
	if !knownLen {
		return false
	}

	if contentLen > 0 {
		return true
	}

	// contentLen is guaranteed to be 0, set content length header for POST, PUT and PATCH even when 0.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		return true
	}

	return false
}

// RequestToHTTP1 maps a bhttp [Request] to a net/http request. The request context will be set to the ctx parameter.
func RequestToHTTP1(ctx context.Context, br *Request, usingProxy, serverSide bool) (*http.Request, error) {
	if !serverSide {
		// TODO: We're currently not supporting decoding client-side requests as we don't need it for our use-case (yet?).
		return nil, fmt.Errorf("not implemented yet: %w", errors.ErrUnsupported)
	}

	hr, err := mapPreBodyToHTTP1ServerSideRequest(ctx, br.ControlData, br.Header, usingProxy)
	if err != nil {
		return nil, err
	}

	if hr.ContentLength == -1 && len(hr.Trailer) == 0 && (br.ContentLength == 0) {
		hr.ContentLength = 0
	}

	if len(hr.Trailer) == 0 {
		hr.Body = io.NopCloser(br.Body)
	} else {
		hr.Body = io.NopCloser(io.MultiReader(
			br.Body,
			newDelayedReader(func() (io.Reader, error) {
				// once we make it here, the body of the bhttp request will have returned EOF
				// and its trailer should be set.
				for key := range br.Trailer {
					for _, val := range br.Trailer.Values(key) {
						hr.Trailer.Add(key, val)
					}
				}
				return eofReader{}, nil
			}),
		))
	}

	return hr, nil
}

// determineHTTPRequestContentLength determines the length of the request content in the same way that Go net/http does. The second
// return parameter indicates whether the request is known length (true) or indeterminate length (false).
func determineHTTPRequestContentLength(hr *http.Request, serverSide bool) (int64, bool, error) {
	if hr.ContentLength == -1 && hr.Body == nil {
		return 0, false, errors.New("indeterminate content length but body is nil")
	}

	if hr.Body == http.NoBody {
		return 0, true, nil
	}

	if chunked(hr.TransferEncoding) {
		return -1, false, nil
	}

	if !serverSide && hr.ContentLength == 0 && hr.Body != nil {
		return 0, false, nil
	}

	return hr.ContentLength, hr.ContentLength >= 0, nil
}

// mapPreBodyFromHTTP1ClientSideRequest interprets the request as a HTTP/1.1 Go client side request
// and returns the appropriate control data and headers for a bhttp request.
//
// Roughly equivalent to the first line and header handling in [http.Request.Write] or [http.Request.WriteProxy].
func mapPreBodyFromHTTP1ClientSideRequest(hr *http.Request, usingProxy bool) (RequestControlData, http.Header, error) {
	method := hr.Method
	if method == "" {
		method = http.MethodGet
	}

	// clients should error when hr.RequestURI is set on a client-side request. So we do the same here.
	if hr.RequestURI != "" {
		return RequestControlData{}, nil, errors.New(".RequestURI field should not be set on client side request")
	}

	targetURI, err := http1ClientRequestTargetURI(hr, usingProxy)
	if err != nil {
		return RequestControlData{}, nil, err
	}

	// default to nil values for the control data unless we discover
	// that we have appropriate values later on.
	control := RequestControlData{
		Method: []byte(method), // :method is always set.
	}

	// set the :scheme pseudo header
	//
	// RFC 9113 Section 8.3.1:
	// Scheme is omitted for CONNECT requests (Section 8.5).
	if method != http.MethodConnect {
		control.Scheme = []byte(hr.URL.Scheme)
	}

	// set the :authority pseudo-header
	//
	// RFC 9113 Section 8.3.1:
	// Clients that generate HTTP/2 requests directly MUST use the ":authority" pseudo-header
	// field to convey authority information, unless there is no authority information to
	// convey (in which case it MUST NOT generate ":authority").
	control.Authority = []byte(targetURI.authority)

	// set the :path pseudo-header.
	//
	// RFC 9113 Section 8.3.1:
	// The ":path" pseudo-header field includes the path and query parts of the target URI.
	//
	// RFC 9113 Section 8.3.1:
	// CONNECT requests (Section 8.5), where the ":path" pseudo-header field is omitted.
	if method != http.MethodConnect {
		control.Path = []byte(targetURI.path)
	}

	header := hr.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}

	// net/http sets these headers from fields on the request and not from the headers. Drop them from
	// the returned headers.
	header.Del("Host")
	// TODO: Look at User-Agent.
	// header.Del("User-Agent")
	header.Del("Content-Length")
	// Note: explicitly not mapped to BHTTP per section 6 of the BHTTP RFC.
	header.Del("Transfer-Encoding")
	header.Del("Trailer")

	// set trailer header if we have any pre-registered keys.
	if len(hr.Trailer) > 0 {
		val, err := trailerToHeaderVal(hr.Trailer)
		if err != nil {
			return RequestControlData{}, nil, fmt.Errorf("failed to compose trailer header: %w", err)
		}

		header.Add("Trailer", val)
	}

	return control, header, nil
}

// mapPreBodyToHTTP1ServerSideRequest interprets the control data and headers as being for a HTTP/1.1 Go server side request
// and sets the appropriate values on the request.
//
// Roughly equivalent to the first line and header handling in [http.ReadRequest].
func mapPreBodyToHTTP1ServerSideRequest(ctx context.Context, ctrlData RequestControlData, h http.Header, usingProxy bool) (*http.Request, error) {
	var err error
	hr := &http.Request{}
	hr.Method = string(ctrlData.Method)

	// validate the method. The use of httpguts.ValidHeaderFieldName looks weird, but is actually
	// the same way net/http validates http methods:
	// https://cs.opensource.google/go/go/+/master:src/net/http/request.go;l=858;bpv=1;bpt=1?q=validMethod&ss=go%2Fgo
	// https://cs.opensource.google/go/go/+/master:src/net/http/http.go?q=symbol%3A%5Cbhttp.isToken%5Cb%20case%3Ayes
	if !httpguts.ValidHeaderFieldName(hr.Method) {
		return nil, InvalidMessageError{
			Err: errors.New("invalid method"),
		}
	}

	// multiple host headers is always wrong.
	if len(h.Values("Host")) > 1 {
		return nil, InvalidMessageError{
			Err: errors.New("multiple host headers"),
		}
	}

	// validate the authority if present.
	hr.Host = string(ctrlData.Authority)
	hasAuthority := len(hr.Host) > 0
	if hasAuthority {
		if !httpguts.ValidHostHeader(hr.Host) {
			return nil, InvalidMessageError{
				Err: errors.New("invalid authority"),
			}
		}
	}

	// validate the host header if present.
	host := h.Get("Host")
	hasHost := len(h.Values("Host")) == 1
	if hasHost {
		if !httpguts.ValidHostHeader(host) {
			return nil, InvalidMessageError{
				Err: errors.New("invalid host header"),
			}
		}
	}

	if hasHost && hasAuthority && host != hr.Host {
		// host and authority must match if we have them both.
		return nil, InvalidMessageError{
			Err: errors.New("non-matching host header and authority"),
		}
	}

	if !hasAuthority && hasHost {
		hr.Host = host
	}

	switch {
	case hr.Method == http.MethodConnect:
		hr.RequestURI = hr.Host
	case usingProxy:
		hr.RequestURI = string(ctrlData.Scheme) + "://" + hr.Host + string(ctrlData.Path)
	default:
		hr.RequestURI = string(ctrlData.Path)
	}

	rawurl := hr.RequestURI
	// CONNECT requests are used two different ways, and neither uses a full URL:
	// The standard use is to tunnel HTTPS through an HTTP proxy.
	// It looks like "CONNECT www.google.com:443 HTTP/1.1", and the parameter is
	// just the authority section of a URL. This information should go in req.URL.Host.
	//
	// The net/rpc package also uses CONNECT, but there the parameter is a path
	// that starts with a slash. It can be parsed with the regular URL parser,
	// and the path will end up in req.URL.Path, where it needs to be in order for
	// RPC to work.
	justAuthority := hr.Method == http.MethodConnect && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		rawurl = "http://" + rawurl
	}

	// Validate the path if its used.
	hr.URL, err = url.ParseRequestURI(rawurl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URI: %w", err)
	}
	if justAuthority {
		// Strip the bogus "http://" back off.
		hr.URL.Scheme = ""
	}

	hr.Proto = "HTTP/1.1"
	hr.ProtoMajor = 1
	hr.ProtoMinor = 1
	hr.Body = http.NoBody

	hr.Header = h
	hr.Header.Del("Host") // delete any host headers as they will have been set in the .Host field.

	// move Content-Length header to ContentLength field if its present.
	if len(hr.Header.Values("Content-Length")) == 1 {
		contentLen, err := strconv.Atoi(hr.Header.Get("Content-Length"))
		if err != nil {
			return nil, InvalidMessageError{
				Err: fmt.Errorf("non-integer content-length header: %w", err),
			}
		}
		if contentLen < 0 {
			return nil, InvalidMessageError{
				Err: fmt.Errorf("content-length header must be positive, got %d", contentLen),
			}
		}
		hr.ContentLength = int64(contentLen)
	} else {
		hr.ContentLength = -1
	}

	// handle the trailer
	if h.Get("Trailer") != "" {
		hr.Trailer, err = parseTrailerHeaderVal(h.Get("Trailer"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse trailer header value: %w", err)
		}
	} else {
		hr.Trailer = http.Header{}
	}
	hr.Header.Del("Trailer")

	return hr.WithContext(ctx), nil
}

type httpTargetURI struct {
	authority string
	path      string
}

// http1ClientRequestTargetURI determines the request target and its form. This logic is adapted
// from the http.Request.write and mirrors the way Go constructs the request target
// for a HTTP 1.1 request.
//
// See for source:
// https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/net/http/request.go;l=673
func http1ClientRequestTargetURI(r *http.Request, usingProxy bool) (httpTargetURI, error) {
	// Find the target host. Prefer the Host: header, but if that
	// is not given, use the host from the request URL.
	//
	// Clean the host, in case it arrives with unexpected stuff in it.
	host := r.Host
	if host == "" {
		if r.URL == nil {
			return httpTargetURI{}, errors.New("bhttp: missing host")
		}
		host = r.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return httpTargetURI{}, err
	}
	// Validate that the Host header is a valid header in general,
	// but don't validate the host itself. This is sufficient to avoid
	// header or request smuggling via the Host field.
	// The server can (and will, if it's a net/http server) reject
	// the request if it doesn't consider the host valid.
	if !httpguts.ValidHostHeader(host) {
		// Historically, we would truncate the Host header after '/' or ' '.
		// Some users have relied on this truncation to convert a network
		// address such as Unix domain socket path into a valid, ignored
		// Host header (see https://go.dev/issue/61431).
		//
		// We don't preserve the truncation, because sending an altered
		// header field opens a smuggling vector. Instead, zero out the
		// Host header entirely if it isn't valid. (An empty Host is valid;
		// see RFC 9112 Section 3.2.)
		//
		// Return an error if we're sending to a proxy, since the proxy
		// probably can't do anything useful with an empty Host header.
		host = ""
		if usingProxy {
			return httpTargetURI{}, errors.New("bhttp: invalid Host header")
		}
	}

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	host = removeZone(host)

	// !!
	// Confsec related changes below:
	//
	// See RFC9112 Section 3.3 on reconstructing the target URI:
	// https://www.rfc-editor.org/rfc/rfc9112#section-3.3

	ruri := r.URL.RequestURI()
	// Default to origin form.
	out := httpTargetURI{
		path:      r.URL.RequestURI(),
		authority: host,
	}

	if usingProxy && r.URL.Scheme != "" && r.URL.Opaque == "" {
		ruri = r.URL.Scheme + "://" + ruri
	} else if r.Method == http.MethodConnect && r.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
		if r.URL.Opaque != "" {
			ruri = r.URL.Opaque
			out.authority = r.URL.Opaque
		}
	}

	if stringContainsCTLByte(ruri) {
		return out, errors.New("bhttp: can't write control character in Request.URL")
	}

	return out, nil
}

// stringContainsCTLByte reports whether s contains any ASCII control character.
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}
	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}
	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}
	return host[:j] + host[i:]
}

func parseTrailerHeaderVal(val string) (http.Header, error) {
	trailers := strings.Split(val, ",")
	out := make(http.Header, len(trailers))
	for _, trailer := range trailers {
		trailer = strings.TrimSpace(trailer)
		if !httpguts.ValidHeaderFieldName(trailer) || !httpguts.ValidTrailerHeader(trailer) {
			return nil, fmt.Errorf("invalid trailer header: %s", trailer)
		}
		out[trailer] = nil
	}
	return out, nil
}

func trailerToHeaderVal(trailer http.Header) (string, error) {
	if len(trailer) == 0 {
		return "", nil
	}

	keys := make([]string, 0, len(trailer))
	for key := range trailer {
		// we check later in the field_lines while encoding. But this allows
		// us to early exit without actually starting the encoding process.
		if !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidTrailerHeader(key) {
			return "", fmt.Errorf("invalid trailer: %s", key)
		}

		keys = append(keys, key)
	}

	// for stable results in tests.
	slices.Sort(keys)

	return strings.Join(keys, ","), nil
}
