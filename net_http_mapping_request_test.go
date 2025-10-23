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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapFromHTTP1Request(t *testing.T) {
	type testCase struct {
		proxy      bool
		serverSide bool
		r          func() *http.Request
		// refLines does a check against the http.RequestWrite method to verify our test case matches the expected HTTP 1.1 request.
		refLines []string
		want     func() *Request
	}
	tests := map[string]testCase{
		"ok, defaults to GET": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, explicit GET": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("http://127.0.0.1/")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, http, no path in url": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("http://127.0.0.1")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST use / as path due to empty path and http scheme.
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, https, no path in url": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("https://127.0.0.1")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST use / as path due to empty path and https scheme.
						[]byte(http.MethodGet), []byte("https"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, non-http-https scheme, no path in url": {
			// RFC 9113 doesn't require it, but Go adds a slash for all schemes in origin-form, not just http/https.
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("ftp://127.0.0.1")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST omit authority due to origin form.
						[]byte(http.MethodGet), []byte("ftp"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, proxy, explicit GET": {
			proxy: true,
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("http://127.0.0.1/")),
				}
			},
			refLines: []string{
				"GET http://127.0.0.1/ HTTP/1.1", // absolute form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, proxy, explicit GET, no path": {
			proxy: true,
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodGet,
					URL:    must(url.Parse("http://127.0.0.1")),
				}
			},
			refLines: []string{
				"GET http://127.0.0.1/ HTTP/1.1", // absolute form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, CONNECT": {
			// Go shouldn't allow CONNECT requests without a port, but it does.
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodConnect,
					URL:    must(url.Parse("http://127.0.0.1")),
				}
			},
			refLines: []string{
				"CONNECT 127.0.0.1 HTTP/1.1", // authority form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST omit scheme due to CONNECT request.
						// MUST omit path due to CONNECT request.
						[]byte(http.MethodConnect), nil, []byte("127.0.0.1"), nil,
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, CONNECT, with port": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodConnect,
					URL:    must(url.Parse("http://127.0.0.1:80")),
				}
			},
			refLines: []string{
				"CONNECT 127.0.0.1:80 HTTP/1.1", // authority form
				"Host: 127.0.0.1:80",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST omit scheme due to CONNECT request.
						// MUST omit path due to CONNECT request.
						[]byte(http.MethodConnect), nil, []byte("127.0.0.1:80"), nil,
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, OPTIONS, origin form": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodOptions,
					URL:    must(url.Parse("http://127.0.0.1/")),
				}
			},
			refLines: []string{
				"OPTIONS / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodOptions), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, OPTIONS, origin form, full path": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodOptions,
					URL:    must(url.Parse("http://127.0.0.1/test?key=val")),
				}
			},
			refLines: []string{
				"OPTIONS /test?key=val HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodOptions), []byte("http"), []byte("127.0.0.1"), []byte("/test?key=val"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, OPTIONS, asterisk form": {
			r: func() *http.Request {
				return &http.Request{
					Method: http.MethodOptions,
					URL: &url.URL{
						Scheme: "http",
						Host:   "127.0.0.1",
						Path:   "*",
					},
				}
			},
			refLines: []string{
				"OPTIONS * HTTP/1.1", // asterisk form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						// MUST use * as path due to asterisk-form.
						[]byte(http.MethodOptions), []byte("http"), []byte("127.0.0.1"), []byte("*"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Host header is overwritten by url host": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Header: http.Header{
						"Host": []string{"127.0.0.2"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Host header is overwritten by Host field": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Host:   "127.0.0.3",
					Header: http.Header{
						"Host": []string{"127.0.0.2"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.3",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.3"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Transfer-Encoding header is dropped": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Header: http.Header{
						"Transfer-Encoding": []string{"chunked"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Content-Length header is dropped": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Header: http.Header{
						"Content-Length": []string{"102"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Trailer header is dropped": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Header: http.Header{
						"Trailer": []string{"X-Test"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Trailer field is used to construct Trailer header": {
			r: func() *http.Request {
				return &http.Request{
					Method:        http.MethodPost,
					URL:           must(url.Parse("http://127.0.0.1/")),
					ContentLength: -1,
					Body:          io.NopCloser(strings.NewReader("")),
					Header:        http.Header{},
					Trailer: http.Header{
						"X-Test-1": nil,
						"X-Test-2": nil,
					},
				}
			},
			refLines: []string{
				"POST / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"Trailer: X-Test-1,X-Test-2",
				"", "0", // empty chunked body. not relevant to the test.
			},
			want: func() *Request {
				return &Request{
					KnownLength: false, ContentLength: -1,
					ControlData: RequestControlData{
						[]byte(http.MethodPost), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Trailer": []string{"X-Test-1,X-Test-2"},
					},
					Body: http.NoBody,
					Trailer: http.Header{
						"X-Test-1": nil,
						"X-Test-2": nil,
					},
				}
			},
		},
		"ok, other headers are not modified": {
			r: func() *http.Request {
				return &http.Request{
					Method: "",
					URL:    must(url.Parse("http://127.0.0.1/")),
					Header: http.Header{
						"Transfer-Encoding": []string{"chunked"},
						"X-Other-Header":    []string{"a"},
					},
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
				"X-Other-Header: a",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"X-Other-Header": []string{"a"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Content-Length is prioritized over Trailer": {
			r: func() *http.Request {
				return &http.Request{
					Method:        http.MethodPost,
					URL:           must(url.Parse("http://127.0.0.1/")),
					ContentLength: 5,
					Body:          io.NopCloser(strings.NewReader("hello")),
					Header:        http.Header{},
					Trailer: http.Header{
						"X-Test": nil,
					},
				}
			},
			refLines: []string{
				"POST / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
				"Content-Length: 5",
			},
			want: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 5,
					ControlData: RequestControlData{
						[]byte(http.MethodPost), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Content-Length": []string{"5"},
					},
					Body:    io.NopCloser(strings.NewReader("hello")),
					Trailer: http.Header{},
				}
			},
		},
		"ok, TransferEncoding prioritized over zero .ContentLength": {
			r: func() *http.Request {
				return &http.Request{
					Method:           "",
					URL:              must(url.Parse("http://127.0.0.1/")),
					Header:           http.Header{},
					TransferEncoding: []string{"chunked"},
					ContentLength:    0,
					Body:             io.NopCloser(strings.NewReader("")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"", "0", // empty chunk, not relevant to the test case.
			},
			want: func() *Request {
				return &Request{
					KnownLength: false, ContentLength: -1,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, TransferEncoding prioritized over non-zero .ContentLength": {
			r: func() *http.Request {
				return &http.Request{
					Method:           "",
					URL:              must(url.Parse("http://127.0.0.1/")),
					Header:           http.Header{},
					TransferEncoding: []string{"chunked"},
					ContentLength:    1,
					Body:             io.NopCloser(strings.NewReader("a")),
				}
			},
			refLines: []string{
				"GET / HTTP/1.1", // origin form
				"Host: 127.0.0.1",
				"User-Agent: Go-http-client/1.1",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"", "1", "a",
				"0", // final chunk, not relevant to the test case.
			},
			want: func() *Request {
				return &Request{
					KnownLength: false, ContentLength: -1,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    io.NopCloser(strings.NewReader("a")),
					Trailer: nil,
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := RequestFromHTTP1(tc.r(), tc.proxy, tc.serverSide)
			require.NoError(t, err)

			requireEqualBHTTPReqs(t, tc.want(), got)

			// verify that mapping this back to a server request gives us a request line that matches
			// the result of net/http.
			gotReq, err := mapPreBodyToHTTP1ServerSideRequest(t.Context(), got.ControlData, got.Header, tc.proxy)
			require.NoError(t, err)

			gotReqLine := fmt.Sprintf("%s %s HTTP/1.1", gotReq.Method, gotReq.RequestURI)
			require.Equal(t, tc.refLines[0], gotReqLine)
		})

		t.Run(name+", verify net/http", func(t *testing.T) {
			t.Parallel()

			got := bytes.NewBuffer(nil)
			var err error
			if !tc.proxy {
				err = tc.r().Write(got)
			} else {
				err = tc.r().WriteProxy(got)
			}
			require.NoError(t, err)

			lines := strings.Split(got.String(), "\r\n")
			require.GreaterOrEqual(t, len(lines), 1)

			gotLines := lines[:len(lines)-2]
			require.Equal(t, tc.refLines, gotLines)
		})
	}

	failTests := map[string]struct {
		r     *http.Request
		proxy bool
	}{
		"fail, .RequestURI field set on client request": {
			r: &http.Request{
				Method:     "",
				URL:        must(url.Parse("http://127.0.0.1")),
				RequestURI: "/test",
			},
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := mapPreBodyFromHTTP1ClientSideRequest(tc.r, tc.proxy)
			require.Error(t, err)
		})
	}
}

func TestMapToHTTP1Request(t *testing.T) {
	tests := map[string]struct {
		ctrlData RequestControlData
		header   http.Header
		r        func() *Request
		want     func() *http.Request // we're only interested in Method, URL, Host, RequestURI and Header in these test cases.
		wantErr  func(t *testing.T, err error)
	}{
		"ok, simple GET, no Host header": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodGet,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, simple GET, matching Host header": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Host":           []string{"127.0.0.1"},
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodGet,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, no authority but has host header": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), nil, []byte("/"),
					},
					Header: http.Header{
						"Host":           []string{"127.0.0.1"},
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodGet,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, CONNECT request": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodConnect), nil, []byte("127.0.0.1:80"), nil,
					},
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodConnect,
					URL:           &url.URL{Host: "127.0.0.1:80", Path: ""},
					Host:          "127.0.0.1:80",
					RequestURI:    "127.0.0.1:80",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, CONNECT request without port": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodConnect), nil, []byte("127.0.0.1"), nil,
					},
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodConnect,
					URL:           &url.URL{Host: "127.0.0.1", Path: ""},
					Host:          "127.0.0.1",
					RequestURI:    "127.0.0.1",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, OPTIONS request with path": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodOptions), []byte("http"), []byte("127.0.0.1"), []byte("/test"),
					},
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodOptions,
					URL:           &url.URL{Path: "/test"},
					Host:          "127.0.0.1",
					RequestURI:    "/test",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, OPTIONS asterisk request": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodOptions), []byte("http"), []byte("127.0.0.1"), []byte("*"),
					},
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodOptions,
					URL:           &url.URL{Path: "*"},
					Host:          "127.0.0.1",
					RequestURI:    "*",
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
		},
		"ok, POST request with Trailer": {
			r: func() *Request {
				return &Request{
					KnownLength: false, ContentLength: -1,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Trailer": []string{"X-Test-1,X-Test-2"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodGet,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: -1,
					Header:        http.Header{},
					Body:          http.NoBody,
					Trailer: http.Header{
						"X-Test-1": nil,
						"X-Test-2": nil,
					},
				}
			},
		},
		"ok. POST request with Content-Length header from known length message": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 12,
					ControlData: RequestControlData{
						[]byte(http.MethodPost), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    strings.NewReader("hello world!"),
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodPost,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: 12,
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    io.NopCloser(strings.NewReader("hello world!")),
					Trailer: http.Header{},
				}
			},
		},
		"ok. POST request with Content-Length header from indeterminate length message": {
			r: func() *Request {
				return &Request{
					KnownLength: false, ContentLength: -1,
					ControlData: RequestControlData{
						[]byte(http.MethodPost), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    strings.NewReader("hello world!"),
					Trailer: http.Header{},
				}
			},
			want: func() *http.Request {
				return &http.Request{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Method:        http.MethodPost,
					URL:           &url.URL{Path: "/"},
					Host:          "127.0.0.1",
					RequestURI:    "/",
					ContentLength: 12,
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    io.NopCloser(strings.NewReader("hello world!")),
					Trailer: http.Header{},
				}
			},
		},
		"fail, invalid byte in method": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte{0x00}, []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, invalid Content-Length header": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Content-Length": []string{"-1"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, invalid byte in authority": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte{0x00}, []byte("/"),
					},
					Header:  http.Header{},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, multiple Host headers": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Host": []string{"127.0.0.1", "127.0.0.1"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, Host header does not match authority": {
			r: func() *Request {
				return &Request{
					KnownLength: true, ContentLength: 0,
					ControlData: RequestControlData{
						[]byte(http.MethodGet), []byte("http"), []byte("127.0.0.1"), []byte("/"),
					},
					Header: http.Header{
						"Host": []string{"127.0.0.3"},
					},
					Body:    http.NoBody,
					Trailer: http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := RequestToHTTP1(t.Context(), tc.r(), false, true)
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}
			require.NoError(t, err)
			want := tc.want().Clone(t.Context())
			requireEqualHTTPReqs(t, want, got)
		})
	}
}

func TestDetermineRequestContentLength(t *testing.T) {
	tests := map[string]struct {
		r             *http.Request
		wantClientLen int64
		wantClient    bool
		wantServerLen int64
		wantServer    bool
		wantHeader    bool // whether we expect the stdlib to include the Content-Length or not.
	}{
		"ok, known-length, GET request with .ContentLength 0 and nil .Body": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodGet,
				ContentLength: 0,
				Body:          nil,
			},
			wantClientLen: 0, wantClient: true,
			wantServerLen: 0, wantServer: true,
			wantHeader: false,
		},
		"ok, known-length, HEAD request with .ContentLength 0 and nil .Body": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodHead,
				ContentLength: 0,
				Body:          nil,
			},
			wantClientLen: 0, wantClient: true,
			wantServerLen: 0, wantServer: true,
			wantHeader: false,
		},
		"ok, known-length, POST request with .ContentLength 0 and nil .Body": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodPost,
				ContentLength: 0,
				Body:          nil,
			},
			wantClientLen: 0, wantClient: true,
			wantServerLen: 0, wantServer: true,
			wantHeader: true,
		},
		"ok, client-indeterminate-length, server-known-length, POST request with .ContentLength 0 and non-nil .Body": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodPost,
				ContentLength: 0,
				Body:          io.NopCloser(strings.NewReader("a")),
			},
			// special case where Go treats client-side requests different from server side requests.
			wantClientLen: 0, wantClient: false,
			wantServerLen: 0, wantServer: true,
			wantHeader: false,
		},
		"ok, known-length, POST request with .ContentLength > 0 and non-nil .Body": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodPost,
				ContentLength: 1,
				Body:          io.NopCloser(strings.NewReader("a")),
			},
			wantClientLen: 1, wantClient: true,
			wantServerLen: 1, wantServer: true,
			wantHeader: true,
		},
		"ok, known-length, GET request with .ContentLength > 0 and non-nil .Body": {
			// bit weird that Go allows this, since GET requests shouldn't have a body.
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodGet,
				ContentLength: 1,
				Body:          io.NopCloser(strings.NewReader("a")),
			},
			wantClientLen: 1, wantClient: true,
			wantServerLen: 1, wantServer: true,
			wantHeader: true,
		},
		"ok, known-length, HEAD request with .ContentLength > 0 and non-nil .Body": {
			// bit weird that Go allows this, since HEAD requests shouldn't have a body.
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodGet,
				ContentLength: 1,
				Body:          io.NopCloser(strings.NewReader("a")),
			},
			wantClientLen: 1, wantClient: true,
			wantServerLen: 1, wantServer: true,
			wantHeader: true,
		},
		"ok, known-length, POST request with .ContentLength 0 and http.NoBody": {
			r: &http.Request{
				URL:           must(url.Parse("http://127.0.0.1")),
				Method:        http.MethodPost,
				ContentLength: 0,
				Body:          http.NoBody,
			},
			wantClientLen: 0, wantClient: true,
			wantServerLen: 0, wantServer: true,
			wantHeader: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotClientLen, gotClient, err := determineHTTPRequestContentLength(tc.r, false)
			require.NoError(t, err)
			require.Equal(t, tc.wantClientLen, gotClientLen)
			require.Equal(t, tc.wantClient, gotClient)

			gotServerLen, gotServer, err := determineHTTPRequestContentLength(tc.r, true)
			require.NoError(t, err)
			require.Equal(t, tc.wantServerLen, gotServerLen)
			require.Equal(t, tc.wantServer, gotServer)
		})

		t.Run(name+", verify go stdlib", func(t *testing.T) {
			t.Parallel()

			got := bytes.NewBuffer(nil)
			err := tc.r.Write(got)
			require.NoError(t, err)

			if tc.wantHeader {
				require.Contains(t, got.String(), "Content-Length")
			} else {
				require.NotContains(t, got.String(), "Content-Length")
			}
		})
	}

	failureTests := map[string]*http.Request{
		// shouldn't even have a body, but just to match behaviour in the stdlib.
		"fail, GET request with .ContentLength -1 and nil .Body": {
			URL:           must(url.Parse("http://127.0.0.1")),
			Method:        http.MethodGet,
			Body:          nil,
			ContentLength: -1,
		},
		// shouldn't even have a body, but just to match behaviour in the stdlib.
		"fail, HEAD request with .ContentLength -1 and nil .Body": {
			URL:           must(url.Parse("http://127.0.0.1")),
			Method:        http.MethodGet,
			Body:          nil,
			ContentLength: -1,
		},
		"fail, POST request with .ContentLength -1 and nil .Body": {
			URL:           must(url.Parse("http://127.0.0.1")),
			Method:        http.MethodPost,
			Body:          nil,
			ContentLength: -1,
		},
	}

	for name, tc := range failureTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := determineHTTPRequestContentLength(tc, false)
			require.Error(t, err)

			_, _, err = determineHTTPRequestContentLength(tc, true)
			require.Error(t, err)
		})

		t.Run(name+", verify go stdlib", func(t *testing.T) {
			t.Parallel()

			got := bytes.NewBuffer(nil)
			err := tc.Write(got)
			require.Error(t, err)
		})
	}
}

func requireEqualHTTPReqs(t *testing.T, want, got *http.Request) {
	t.Helper()

	// read both bodies and make sure they're the same so we can just
	// compare the requests using require.Equal
	wantBdy, err := io.ReadAll(want.Body)
	require.NoError(t, err)
	want.Body = nil

	gotBdy, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	got.Body = nil

	require.Equal(t, wantBdy, gotBdy)
	require.Equal(t, want, got)
}

func requireEqualBHTTPReqs(t *testing.T, want, got *Request) {
	t.Helper()

	// read both bodies and make sure they're the same so we can just
	// compare the requests using require.Equal
	wantBdy, err := io.ReadAll(want.Body)
	require.NoError(t, err)
	want.Body = nil

	gotBdy, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	got.Body = nil

	require.Equal(t, wantBdy, gotBdy)
	require.Equal(t, want, got)
}
