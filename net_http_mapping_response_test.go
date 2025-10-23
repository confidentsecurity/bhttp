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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapFromHTTP1Response(t *testing.T) {
	tests := map[string]struct {
		r func() *http.Response
		// refLines is checked against the http.Reponse.Write method to verify our test case matches the expected HTTP 1.1 response.
		refLines []string
		want     func() *Response
	}{
		"ok, 200 status code": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusOK,
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, 301 status code": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusMovedPermanently,
				}
			},
			refLines: []string{
				"HTTP/1.1 301 Moved Permanently",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusMovedPermanently,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, 400 status code": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusBadRequest,
				}
			},
			refLines: []string{
				"HTTP/1.1 400 Bad Request",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusBadRequest,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, 500 status code": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusInternalServerError,
				}
			},
			refLines: []string{
				"HTTP/1.1 500 Internal Server Error",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusInternalServerError,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, original Content-Length header is ignored if it doesn't match ContentLength field": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode:    http.StatusOK,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"102"},
					},
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, original Transfer-Encoding header is dropped": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Transfer-Encoding": []string{"chunked"},
					},
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				"Content-Length: 0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, Trailer header is dropped from original": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Trailer": []string{"X-Test"},
					},
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				"Content-Length: 0", // always added by net/http.
			},
			want: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{"Content-Length": []string{"0"}},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
		},
		"ok, Trailer field is used to construct Trailer header": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode:       http.StatusOK,
					Header:           http.Header{},
					ContentLength:    -1,
					TransferEncoding: []string{"chunked"},
					Body:             io.NopCloser(strings.NewReader("")),
					Trailer: http.Header{
						"X-Test-1": nil,
						"X-Test-2": nil,
					},
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"Trailer: X-Test-1,X-Test-2",
				"", "0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Trailer": []string{"X-Test-1,X-Test-2"},
					},
					Body: io.NopCloser(strings.NewReader("")),
					Trailer: http.Header{
						"X-Test-1": nil,
						"X-Test-2": nil,
					},
				}
			},
		},
		// opposite of what happens with client-side requests, but okay. follow what net/http does.
		"ok, Trailer is prioritized over Content-Length": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode:       http.StatusOK,
					Header:           http.Header{},
					ContentLength:    5,
					TransferEncoding: []string{"chunked"},
					Body:             io.NopCloser(strings.NewReader("hello")),
					Trailer: http.Header{
						"X-Test": nil,
					},
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"Trailer: X-Test",
				"", "5", "hello", "0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Trailer": []string{"X-Test"},
					},
					Body: io.NopCloser(strings.NewReader("hello")),
					Trailer: http.Header{
						"X-Test": nil,
					},
				}
			},
		},
		"ok, TransferEncoding is prioritized over zero .ContentLength": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode:       http.StatusOK,
					Header:           http.Header{},
					ContentLength:    0,
					TransferEncoding: []string{"chunked"},
					Body:             io.NopCloser(strings.NewReader("a")),
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"", "1", "a", "0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{},
					Body:            io.NopCloser(strings.NewReader("a")),
				}
			},
		},
		"ok, TransferEncoding is prioritized over non-zero .ContentLength": {
			r: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					StatusCode:       http.StatusOK,
					Header:           http.Header{},
					ContentLength:    1,
					TransferEncoding: []string{"chunked"},
					Body:             io.NopCloser(strings.NewReader("a")),
				}
			},
			refLines: []string{
				"HTTP/1.1 200 OK",
				// net/http adds the Transfer-Encoding: chunked header.
				//
				// It's explicitly not added to the BHTTP representation as
				// per section 6 of the RFC, Transfer-Encoding is not used:
				// https://datatracker.ietf.org/doc/html/rfc9292#differences
				"Transfer-Encoding: chunked",
				"", "1", "a", "0",
			},
			want: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1,
					Informational:   nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader:     http.Header{},
					Body:            io.NopCloser(strings.NewReader("a")),
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := MapFromHTTP1Response(tc.r())
			require.NoError(t, err)

			requireEqualBHTTPResps(t, tc.want(), got)
		})

		t.Run(name+", verify net/http", func(t *testing.T) {
			t.Parallel()

			got := bytes.NewBuffer(nil)
			err := tc.r().Write(got)
			require.NoError(t, err)

			lines := strings.Split(got.String(), "\r\n")
			require.GreaterOrEqual(t, len(lines), 1)

			gotLines := lines[:len(lines)-2]
			require.Equal(t, tc.refLines, gotLines)
		})
	}

	failTests := map[string]*http.Response{
		"fail, negative status code": {
			StatusCode: -1,
		},
		"fail, valid non-final status code": {
			StatusCode: http.StatusContinue,
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := mapPreBodyFromHTTP1Response(tc)
			require.Error(t, err)
		})
	}
}

func TestMapToHTTP1Response(t *testing.T) {
	tests := map[string]struct {
		r       func() *Response
		want    func() *http.Response
		wantErr func(t *testing.T, err error)
	}{
		"ok, 200 status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, 301 status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: http.StatusMovedPermanently,
					FinalHeader: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "301 Moved Permanently",
					StatusCode:    http.StatusMovedPermanently,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, 400 status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: http.StatusBadRequest,
					FinalHeader: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "400 Bad Request",
					StatusCode:    http.StatusBadRequest,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, 500 status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: http.StatusInternalServerError,
					FinalHeader: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "500 Internal Server Error",
					StatusCode:    http.StatusInternalServerError,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, max final status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: 599,
					FinalHeader: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "599",
					StatusCode:    599,
					ContentLength: 0,
					Header: http.Header{
						"Content-Length": []string{"0"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
		},
		"ok, Trailer": {
			r: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1, Informational: nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Trailer": []string{"X-Test-1,X-Test-2"},
					},
					Body:    http.NoBody,
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
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
		"ok, response with Content-Length header from known length message": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 12, Informational: nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    strings.NewReader("hello world!"),
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
					ContentLength: 12,
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    io.NopCloser(strings.NewReader("hello world!")),
					Trailer: nil,
				}
			},
		},
		"ok, response with Content-Length header from indeterminate length message": {
			r: func() *Response {
				return &Response{
					KnownLength: false, ContentLength: -1, Informational: nil,
					FinalStatusCode: http.StatusOK,
					FinalHeader: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    strings.NewReader("hello world!"),
					Trailer: nil,
				}
			},
			want: func() *http.Response {
				return &http.Response{
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Status:        "200 OK",
					StatusCode:    http.StatusOK,
					ContentLength: 12,
					Header: http.Header{
						"Content-Length": []string{"12"},
					},
					Body:    io.NopCloser(strings.NewReader("hello world!")),
					Trailer: nil,
				}
			},
		},
		"fail, negative status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: -1,
					FinalHeader:     http.Header{},
					Body:            http.NoBody,
					Trailer:         http.Header{},
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, non-final status code": {
			r: func() *Response {
				return &Response{
					KnownLength: true, ContentLength: 0, Informational: nil,
					FinalStatusCode: http.StatusContinue,
					FinalHeader:     http.Header{},
					Body:            http.NoBody,
					Trailer:         http.Header{},
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

			got, err := MapToHTTP1Response(tc.r())
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}
			require.NoError(t, err)

			requireEqualHTTPResps(t, tc.want(), got)
		})
	}
}

func TestDetermineResponseContentLength(t *testing.T) {
	tests := map[string]struct {
		r            func() *http.Response
		wantLen      int64
		wantKnownLen bool
		wantHeader   bool // whether we expect the stdlib to include the Content-Length or not.
	}{
		"ok, known-length, .ContentLength 0 and nil .Body": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: 0,
					Body:          nil,
				}
			},
			wantLen: 0, wantKnownLen: true,
			wantHeader: true,
		},
		"ok, known-length, .ContentLength 1 and non-nil .Body": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: 1,
					Body:          io.NopCloser(strings.NewReader("a")),
				}
			},
			wantLen: 1, wantKnownLen: true,
			wantHeader: true,
		},
		"ok, known-length, .ContentLength 0 and non-nil .Body but empty reader": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: 0,
					Body:          io.NopCloser(strings.NewReader("")),
				}
			},
			wantLen: 0, wantKnownLen: true,
			wantHeader: true,
		},
		"ok, indeterminate-length, .ContentLength 0 and body with content": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: 0,
					Body:          io.NopCloser(strings.NewReader("a")),
				}
			},
			wantLen: -1, wantKnownLen: false,
			wantHeader: false,
		},
		"ok, indeterminate-length, .ContentLength -1 and nil body": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: -1,
					Body:          nil,
				}
			},
			wantLen: -1, wantKnownLen: false,
			wantHeader: false,
		},
		"ok, indeterminate-length, .ContentLength -1 and body with content": {
			r: func() *http.Response {
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: -1,
					Body:          io.NopCloser(strings.NewReader("a")),
				}
			},
			wantLen: -1, wantKnownLen: false,
			wantHeader: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gotLen, knownLen, err := determineHTTPResponseContentLength(tc.r())
			require.NoError(t, err)
			require.Equal(t, tc.wantKnownLen, knownLen)
			require.Equal(t, tc.wantLen, gotLen)
		})

		t.Run(name+", verify go stdlib", func(t *testing.T) {
			t.Parallel()

			got := bytes.NewBuffer(nil)
			err := tc.r().Write(got)
			require.NoError(t, err)

			if tc.wantHeader {
				require.Contains(t, got.String(), "Content-Length")
			} else {
				require.NotContains(t, got.String(), "Content-Length")
			}
		})
	}
}

func requireEqualHTTPResps(t *testing.T, want, got *http.Response) {
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

func requireEqualBHTTPResps(t *testing.T, want, got *Response) {
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
