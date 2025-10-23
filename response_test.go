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
	"cmp"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type responseRoundTripTest struct {
	original    func() *http.Response
	encoder     func() *ResponseEncoder
	decoder     func() *ResponseDecoder
	wantEncoded func() []byte
	truncate    []int
	wantDecoded func() *http.Response
}

func newResponseTestCases() map[string]responseRoundTripTest {
	// RFC example response
	newRFCExampleOriginal := func() *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Date":          []string{"Mon, 27 Jul 2009 12:28:53 GMT"},
				"Server":        []string{"Apache"},
				"Last-Modified": []string{"Wed, 22 Jul 2009 19:15:56 GMT"},
				"ETag":          []string{"\"34aa387-d-1568eb00\""},
				"Accept-Ranges": []string{"bytes"},
				"Vary":          []string{"Accept-Encoding"},
				"Content-Type":  []string{"text/plain"},
			},
			ContentLength: 51,
			Body:          io.NopCloser(strings.NewReader("Hello World! My content includes a trailing CRLF.\r\n")),
		}
	}

	newRFCExampleEncoder := func() *ResponseEncoder {
		enc := &ResponseEncoder{}
		enc.MapFunc = func(r *http.Response) (*Response, error) {
			resp, err := MapFromHTTP1Response(r)
			if err != nil {
				return nil, err
			}
			// due to .ContentLength > 0 we default to encoding this response using known-length encoding.
			resp.KnownLength = false
			resp.ContentLength = -1
			// add the informational responses that the example uses.
			resp.Informational = []InformationalResponse{
				{
					StatusCode: http.StatusProcessing,
					Header: http.Header{
						"Running": []string{"\"sleep 15\""},
					},
				},
				{
					StatusCode: http.StatusEarlyHints,
					Header: http.Header{
						"Link": []string{
							"</style.css>; rel=preload; as=style",
							"</script.js>; rel=preload; as=script",
						},
					},
				},
			}

			return resp, nil
		}
		enc.orderFieldLinesFunc = func(lines []fieldLine) {
			order := map[string]int{
				"date":           0,
				"server":         1,
				"last-modified":  2,
				"etag":           3,
				"accept-ranges":  4,
				"content-length": 5,
				"vary":           6,
				"content-type":   7,
			}
			slices.SortFunc(lines, func(x, y fieldLine) int {
				orderX := order[string(x.name)]
				orderY := order[string(y.name)]
				return cmp.Compare(orderX, orderY)
			})
		}
		return enc
	}

	// hello world response (short response with known-lenght body)
	newHelloWorldOriginal := func() *http.Response {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			ContentLength: 12,
			Body:          io.NopCloser(strings.NewReader("Hello world!")),
		}
	}

	newHellowWorldKnownLenEncoded := func() []byte {
		return []byte{
			// known length response frame
			1,
			// final response control data (status code),
			0x40, 0xC9, // quic encoded 201
			// final response header
			13 + 11 + 15 + 3,
			14, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h',
			2, '1', '2',
			12, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e',
			10, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
			// body
			12, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			// empty trailer field section
			0,
		}
	}

	newHelloWorldIndeterminateLenEncoded := func() []byte {
		return []byte{
			// indeterminate length response frame
			3,
			// final response control data (status code),
			0x40, 0xC9, // quic encoded 201
			// final response header
			14, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 'l', 'e', 'n', 'g', 't', 'h',
			2, '1', '2',
			12, 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e',
			10, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
			0,
			// body
			12, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			0,
			// empty trailer field section
			0,
		}
	}

	newHelloWorldDecoded := func() *http.Response {
		return &http.Response{
			Status: "201 Created", StatusCode: http.StatusCreated,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{
				"Content-Type":   []string{"text/plain"},
				"Content-Length": []string{"12"},
			},
			ContentLength: 12,
			Body:          io.NopCloser(strings.NewReader("Hello world!")),
		}
	}

	// response with trailers
	newTrailersOriginal := func() *http.Response {
		trailer := http.Header{
			"X-Test-1": nil,
			"X-Test-2": nil,
		}
		return &http.Response{
			StatusCode:    http.StatusCreated,
			Header:        http.Header{},
			ContentLength: -1,
			Body: io.NopCloser(&eofCallback{
				r: strings.NewReader("Hello world!"),
				callback: func() {
					trailer.Add("X-Test-1", "foo")
					trailer.Add("X-Test-1", "bar")
					trailer.Add("X-Test-2", "baz")
				},
			}),
			Trailer: trailer,
		}
	}

	newTrailersIndeterminateLenEncoded := func() []byte {
		return []byte{
			// unknown length response frame
			3,
			// final response control data (status code),
			0x40, 0xC9, // quic encoded 201
			// final response header field section.
			7, 't', 'r', 'a', 'i', 'l', 'e', 'r',
			17, 'X', '-', 'T', 'e', 's', 't', '-', '1', ',', 'X', '-', 'T', 'e', 's', 't', '-', '2',
			0,
			// content chunks
			12, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			0,
			// trailer field section
			8, 'x', '-', 't', 'e', 's', 't', '-', '1',
			3, 'f', 'o', 'o',
			8, 'x', '-', 't', 'e', 's', 't', '-', '1',
			3, 'b', 'a', 'r',
			8, 'x', '-', 't', 'e', 's', 't', '-', '2',
			3, 'b', 'a', 'z',
			0,
		}
	}

	newTrailersKnownLenEncoded := func() []byte {
		return []byte{
			// known length response frame
			1,
			// final response control data (status code),
			0x40, 0xC9, // quic encoded 201
			// final response header field section.
			26,
			7, 't', 'r', 'a', 'i', 'l', 'e', 'r',
			17, 'X', '-', 'T', 'e', 's', 't', '-', '1', ',', 'X', '-', 'T', 'e', 's', 't', '-', '2',
			// content chunks
			12, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			// trailer field section
			39,
			8, 'x', '-', 't', 'e', 's', 't', '-', '1',
			3, 'f', 'o', 'o',
			8, 'x', '-', 't', 'e', 's', 't', '-', '1',
			3, 'b', 'a', 'r',
			8, 'x', '-', 't', 'e', 's', 't', '-', '2',
			3, 'b', 'a', 'z',
		}
	}

	newTrailersDecoded := func() *http.Response {
		return &http.Response{
			Status: "201 Created", StatusCode: http.StatusCreated,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{},
			ContentLength: -1,
			Body:          io.NopCloser(strings.NewReader("Hello world!")),
			Trailer: http.Header{
				"X-Test-1": []string{"foo", "bar"},
				"X-Test-2": []string{"baz"},
			},
		}
	}

	return map[string]responseRoundTripTest{
		"ok, RFC example, indeterminate length": {
			original: newRFCExampleOriginal,
			encoder:  newRFCExampleEncoder,
			wantEncoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-response-example
				//
				const s = `03406607 72756e6e 696e670a 22736c65
						   65702031 35220040 67046c69 6e6b233c
						   2f737479 6c652e63 73733e3b 2072656c
						   3d707265 6c6f6164 3b206173 3d737479
						   6c65046c 696e6b24 3c2f7363 72697074
						   2e6a733e 3b207265 6c3d7072 656c6f61
						   643b2061 733d7363 72697074 0040c804
						   64617465 1d4d6f6e 2c203237 204a756c
						   20323030 39203132 3a32383a 35332047
						   4d540673 65727665 72064170 61636865
						   0d6c6173 742d6d6f 64696669 65641d57
						   65642c20 3232204a 756c2032 30303920
						   31393a31 353a3536 20474d54 04657461
						   67142233 34616133 38372d64 2d313536
						   38656230 30220d61 63636570 742d7261
						   6e676573 05627974 65730e63 6f6e7465
						   6e742d6c 656e6774 68023531 04766172
						   790f4163 63657074 2d456e63 6f64696e
						   670c636f 6e74656e 742d7479 70650a74
						   6578742f 706c6169 6e003348 656c6c6f
						   20576f72 6c642120 4d792063 6f6e7465
						   6e742069 6e636c75 64657320 61207472
						   61696c69 6e672043 524c462e 0d0a0000`

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			truncate: []int{
				1, // truncate trailer
			},
			decoder: func() *ResponseDecoder {
				return &ResponseDecoder{
					MapFunc: func(ctx context.Context, r *Response) (*http.Response, error) {
						r.KnownLength = true
						r.ContentLength = 51
						result, err := MapToHTTP1Response(r)
						if err != nil {
							return result, err
						}
						return result, nil
					},
				}
			},
			wantDecoded: func() *http.Response {
				return &http.Response{
					Status: "200 OK", StatusCode: http.StatusOK,
					Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Header: http.Header{
						"Date":           []string{"Mon, 27 Jul 2009 12:28:53 GMT"},
						"Server":         []string{"Apache"},
						"Last-Modified":  []string{"Wed, 22 Jul 2009 19:15:56 GMT"},
						"Etag":           []string{"\"34aa387-d-1568eb00\""},
						"Accept-Ranges":  []string{"bytes"},
						"Content-Length": []string{"51"},
						"Vary":           []string{"Accept-Encoding"},
						"Content-Type":   []string{"text/plain"},
					},
					ContentLength: 51,
					Body:          io.NopCloser(strings.NewReader("Hello World! My content includes a trailing CRLF.\r\n")),
				}
			},
		},
		"ok, hello world, default encoder": {
			original:    newHelloWorldOriginal,
			wantEncoded: newHellowWorldKnownLenEncoded,
			wantDecoded: newHelloWorldDecoded,
		},
		"ok, hello world, known length encoder": {
			original:    newHelloWorldOriginal,
			wantEncoded: newHellowWorldKnownLenEncoded,
			encoder: func() *ResponseEncoder {
				return NewKnownLengthResponseEncoder()
			},
			wantDecoded: newHelloWorldDecoded,
		},
		"ok, hello world, indeterminate length encoder": {
			original: newHelloWorldOriginal,
			encoder: func() *ResponseEncoder {
				return NewIndeterminateLengthResponseEncoder()
			},
			wantEncoded: newHelloWorldIndeterminateLenEncoded,
			wantDecoded: newHelloWorldDecoded,
		},
		"ok, trailers, default encoder": {
			original:    newTrailersOriginal,
			wantEncoded: newTrailersIndeterminateLenEncoded,
			wantDecoded: newTrailersDecoded,
		},
		"ok, trailers, known length encoder": {
			original: newTrailersOriginal,
			encoder: func() *ResponseEncoder {
				return NewKnownLengthResponseEncoder()
			},
			wantEncoded: newTrailersKnownLenEncoded,
			wantDecoded: newTrailersDecoded,
		},
		"ok, trailers, indeterminate length encoder": {
			original: newTrailersOriginal,
			encoder: func() *ResponseEncoder {
				return NewIndeterminateLengthResponseEncoder()
			},
			wantEncoded: newTrailersIndeterminateLenEncoded,
			wantDecoded: newTrailersDecoded,
		},
	}
}

func TestEncodeDecodeResponseRoundTrip(t *testing.T) {
	test := newResponseTestCases()
	for name, tc := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			enc := &ResponseEncoder{}
			dec := &ResponseDecoder{}
			if tc.encoder != nil {
				enc = tc.encoder()
			}
			if tc.decoder != nil {
				dec = tc.decoder()
			}

			msg, err := enc.EncodeResponse(tc.original())
			require.NoError(t, err)

			require.False(t, msg.IsRequest())
			require.True(t, msg.IsResponse())

			respBytes, err := io.ReadAll(msg)
			require.NoError(t, err)

			require.Equal(t, tc.wantEncoded(), respBytes)

			encReader := bytes.NewReader(respBytes)
			got, err := dec.DecodeResponse(t.Context(), encReader)
			require.NoError(t, err)

			want := tc.wantDecoded()
			requireEqualHTTPResps(t, want, got)

			// verify the full reader was consumed during body reading, ensuring
			// no trailing padding bytes remain.
			require.Equal(t, 0, encReader.Len())

			// also test the truncated encodings.
			for _, truncate := range tc.truncate {
				truncatedBytes := respBytes[:len(respBytes)-truncate]

				got, err := dec.DecodeResponse(t.Context(), bytes.NewReader(truncatedBytes))
				require.NoError(t, err, truncate)

				want := tc.wantDecoded()
				requireEqualHTTPResps(t, want, got)
			}
		})
	}
}

func TestTrailersWithResponseWriter(t *testing.T) {

	tests := map[string]struct {
		handler                http.HandlerFunc
		expectedBody           string
		expectedPresetTrailers http.Header
		expectedTrailers       http.Header
	}{
		"ok, All expected trailers": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "AtEnd1, AtEnd2")
				w.Header().Add("Trailer", "AtEnd3")

				w.WriteHeader(http.StatusOK)

				w.Header().Set("AtEnd1", "value 1")
				w.Write([]byte(`{"message": "Hello from Go!"}`))

				w.Header().Set("AtEnd2", "value 2")
				w.Header().Set("AtEnd3", "value 3")
			},
			expectedTrailers: http.Header{
				"Atend1": []string{"value 1"},
				"Atend2": []string{"value 2"},
				"Atend3": []string{"value 3"},
			},
			expectedBody: `{"message": "Hello from Go!"}`,
		},
		"ok, Empty Body": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "AtEnd1, AtEnd2")
				w.Header().Add("Trailer", "AtEnd3")

				w.WriteHeader(http.StatusOK)

				w.Header().Set("AtEnd1", "value 1")

				w.Header().Set("AtEnd2", "value 2")
				w.Header().Set("AtEnd3", "value 3")
			},
			expectedTrailers: http.Header{
				"Atend1": []string{"value 1"},
				"Atend2": []string{"value 2"},
				"Atend3": []string{"value 3"},
			},
			expectedBody: "",
		},
		"ok, Prefix Named Trailer": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "AtEnd1, AtEnd2 ")

				w.WriteHeader(http.StatusOK)

				w.Header().Set("AtEnd1", "value 1")
				w.Write([]byte(`{"message": "Hello from Go!"}`))

				w.Header().Set("AtEnd2", "value 2")
				w.Header().Set(http.TrailerPrefix+"AtEnd3", "value 3") // Golang uses a special prefix to indicate that a header is a trailer post-WriteHeader
			},
			expectedPresetTrailers: http.Header{
				"Atend1": nil,
				"Atend2": nil,
			},
			expectedTrailers: http.Header{
				"Atend1": []string{"value 1"},
				"Atend2": []string{"value 2"},
				"Atend3": []string{"value 3"},
			},
			expectedBody: `{"message": "Hello from Go!"}`,
		},
		"ok, Non pre-set Trailer": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "AtEnd1, AtEnd2")

				w.WriteHeader(http.StatusOK)

				w.Header().Set("AtEnd1", "value 1")
				w.Write([]byte(`{"message": "Hello from Go!"}`))

				w.Header().Set("AtEnd2", "value 2")
				w.Header().Set("AtEnd3", "value 3") // This trailer was not specified in the initial request, so should not show up in the response
			},
			expectedTrailers: http.Header{
				"Atend1": []string{"value 1"},
				"Atend2": []string{"value 2"},
			},
			expectedBody: `{"message": "Hello from Go!"}`,
		},
		// note, the go response object does not represent informational responses so these aren't really encoded in bhttp as is.
		"ok, Set Informational Responses": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusContinue)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "AtEnd1, AtEnd2")

				w.WriteHeader(http.StatusContinue)
				w.WriteHeader(http.StatusContinue)
				w.WriteHeader(http.StatusContinue)
				w.WriteHeader(http.StatusContinue)
				w.Header().Set("AtEnd2", "value 2")
				w.WriteHeader(http.StatusContinue)

				w.WriteHeader(http.StatusOK)

				w.Write([]byte(`{"message": "Hello from Go!"}`))
				w.Header().Set("AtEnd1", "value 1")
			},
			expectedTrailers: http.Header{
				"Atend1": []string{"value 1"},
				"Atend2": []string{"value 2"},
			},
			expectedBody: `{"message": "Hello from Go!"}`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			res, err := http.Get(ts.URL)
			require.NoError(t, err)

			encoder := &ResponseEncoder{}
			// encode the request
			msg, err := encoder.EncodeResponse(res)
			require.NoError(t, err)

			decoder := &ResponseDecoder{}

			decodedResp, err := decoder.DecodeResponse(ctx, msg)
			require.NoError(t, err)

			require.Equal(t, "application/json", decodedResp.Header.Get("Content-Type"))

			// except for a single test where we're being fancy,
			// we expect the preset trailers to have the same names but be empty
			// as the eventual expected trailers
			var expectedPresetTrailers http.Header
			if tc.expectedPresetTrailers != nil {
				expectedPresetTrailers = tc.expectedPresetTrailers
			} else {
				expectedPresetTrailers = make(http.Header)
				for name := range tc.expectedTrailers {
					expectedPresetTrailers[name] = nil
				}
			}
			require.EqualValues(t, expectedPresetTrailers, decodedResp.Trailer)

			// Reading the body triggers reading the trailers
			decodeBodyBytes, err := io.ReadAll(decodedResp.Body)
			require.NoError(t, err)
			err = decodedResp.Body.Close()
			require.NoError(t, err)

			require.Equal(t, tc.expectedBody, string(decodeBodyBytes))

			require.EqualValues(t, tc.expectedTrailers, decodedResp.Trailer)
		})
	}
}

func TestConstructedResponse(t *testing.T) {
	content := []byte(`{"status": "success"}`)

	tests := map[string]struct {
		resp                   func() *http.Response
		expectedBody           []byte
		expectedPresetTrailers http.Header
		expectedTrailers       http.Header
	}{
		"ok, clean": {
			resp: func() *http.Response {
				response := &http.Response{
					Status:     "OK",
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(content)),
				}

				response.Header = make(http.Header)
				response.Header.Set("Content-Type", "application/json")
				response.Header.Set("Server", "test-server")
				response.Header["X-Custom"] = []string{"value1", "value2"}
				response.Header.Set("Cache-Control", "no-cache")

				// Set trailers
				response.Trailer = make(http.Header)
				response.Trailer.Set("Trailer1", "value1")
				response.Trailer.Set("Trailer2", "value2")

				return response
			},
			expectedBody: content,
			expectedTrailers: http.Header{
				"Trailer1": []string{"value1"},
				"Trailer2": []string{"value2"},
			},
		},
		"ok, known length": {
			resp: func() *http.Response {
				response := &http.Response{
					Status:     "OK",
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(content)),
				}

				response.Header = make(http.Header)
				response.Header.Set("Content-Type", "application/json")
				response.Header.Set("Server", "test-server")
				response.Header["X-Custom"] = []string{"value1", "value2"}
				response.Header.Set("Cache-Control", "no-cache")
				// response.Header.Set("Content-Length", strconv.Itoa(len(content)))
				response.ContentLength = int64(len(content))

				// Set trailers
				response.Trailer = make(http.Header)
				response.Trailer.Set("Trailer1", "value1")
				response.Trailer.Set("Trailer2", "value2")

				return response
			},
			expectedBody:     content,
			expectedTrailers: nil,
		},
		"ok, empty plus trailers": {
			resp: func() *http.Response {
				response := &http.Response{
					Status:     "OK",
					StatusCode: http.StatusOK,
					Body:       http.NoBody,
				}

				response.Header = make(http.Header)
				response.Header.Set("Content-Type", "application/json")
				response.Header.Set("Server", "test-server")
				response.Header["X-Custom"] = []string{"value1", "value2"}
				response.Header.Set("Cache-Control", "no-cache")

				// Set trailers
				response.Trailer = make(http.Header)
				response.Trailer.Set("Trailer1", "value1")
				response.Trailer.Set("Trailer2", "value2")

				return response
			},
			expectedBody:     []byte{},
			expectedTrailers: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			encoder := &ResponseEncoder{}
			msg, err := encoder.EncodeResponse(tc.resp())
			require.NoError(t, err)

			decoder := &ResponseDecoder{}
			decodedResp, err := decoder.DecodeResponse(ctx, msg)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, decodedResp.StatusCode)
			require.Equal(t, "application/json", decodedResp.Header.Get("Content-Type"))
			require.Equal(t, "test-server", decodedResp.Header.Get("Server"))
			require.Equal(t, []string{"value1", "value2"}, decodedResp.Header["X-Custom"])
			require.Equal(t, "no-cache", decodedResp.Header.Get("Cache-Control"))

			// Verify body content
			bodyBytes, err := io.ReadAll(decodedResp.Body)
			decodedResp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, tc.expectedBody, bodyBytes)

			require.EqualValues(t, tc.expectedTrailers, decodedResp.Trailer)

		})
	}
}
