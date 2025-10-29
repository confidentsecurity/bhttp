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
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

type requestRoundTripTest struct {
	original    func() *http.Request
	encoder     func() *RequestEncoder
	decoder     func() *RequestDecoder
	wantEncoded func() []byte
	truncate    []int
	wantDecoded func() *http.Request
}

func newRequestTestCases() map[string]requestRoundTripTest {
	newRFCExampleOriginal := func() *http.Request {
		// Go representation of the RFC example request from
		// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
		return &http.Request{
			Method: http.MethodGet,
			URL:    must(url.Parse("https://www.example.com/hello.txt")),
			Header: http.Header{
				"User-Agent":      []string{"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"},
				"Accept-Language": []string{"en, mi"},
			},
		}
	}

	newRFCExampleEncoder := func() *RequestEncoder {
		return &RequestEncoder{
			// Allow tests to overwrite the map func.
			MapFunc: func(req *http.Request) (*Request, error) {
				r, err := DefaultRequestFromHTTP(req)
				if err != nil {
					return nil, err
				}
				r.Header.Del("Content-Length") // not included in example eventhough this is a fixed length request.

				// There is an inconsistency in RFC9292, where it acts as if RFC9113's (2022) authority handling
				// is the same as in the now obsolute RFC7540 (2015)
				//
				// These two lines fix the authority and Host header follow RFC7540's approach to authority.
				r.ControlData.Authority = nil
				r.Header["Host"] = []string{"www.example.com"}
				return r, nil
			},
			orderFieldLinesFunc: func(lines []fieldLine) {
				// order the field lines, so we have a stable binary representation we can match against.
				order := map[string]int{
					"user-agent":      0,
					"host":            1,
					"accept-language": 2,
				}
				slices.SortFunc(lines, func(x, y fieldLine) int {
					orderX := order[string(x.name)]
					orderY := order[string(y.name)]
					return cmp.Compare(orderX, orderY)
				})
			},
		}
	}

	newRFCExampleDecoded := func(contentLength int64) *http.Request {
		return &http.Request{
			Method:        http.MethodGet,
			URL:           &url.URL{Path: "/hello.txt"},
			Host:          "www.example.com",
			ContentLength: contentLength,
			RequestURI:    "/hello.txt",
			Header: http.Header{
				"User-Agent":      []string{"curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3"},
				"Accept-Language": []string{"en, mi"},
			},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       http.NoBody,
			Trailer:    http.Header{},
		}
	}

	newPostWithTrailerOriginal := func() *http.Request {
		trailer := http.Header{
			"X-Test-1": nil,
			"X-Test-2": nil,
		}
		return &http.Request{
			Method:        http.MethodPost,
			URL:           must(url.Parse("https://www.example.com/hello.txt")),
			ContentLength: -1,
			Trailer:       trailer,
			Body: io.NopCloser(&eofCallback{
				r: strings.NewReader("Hello world!"),
				callback: func() {
					trailer.Add("X-Test-1", "foo")
					trailer.Add("X-Test-1", "bar")
					trailer.Add("X-Test-2", "baz")
				},
			}),
		}
	}

	newPostWithTrailersIndetermininateLenEncoded := func() []byte {
		return []byte{
			// indeterminate length request frame.
			2,
			// request control data
			4, 'P', 'O', 'S', 'T',
			5, 'h', 't', 't', 'p', 's',
			15, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			10, '/', 'h', 'e', 'l', 'l', 'o', '.', 't', 'x', 't',
			// header field section.
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

	newPostWithTrailersKnownLenEncoded := func() []byte {
		return []byte{
			// known len request frame
			0,
			// request control data
			4, 'P', 'O', 'S', 'T',
			5, 'h', 't', 't', 'p', 's',
			15, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			10, '/', 'h', 'e', 'l', 'l', 'o', '.', 't', 'x', 't',
			// header field section.
			26,
			7, 't', 'r', 'a', 'i', 'l', 'e', 'r',
			17, 'X', '-', 'T', 'e', 's', 't', '-', '1', ',', 'X', '-', 'T', 'e', 's', 't', '-', '2',
			// content section
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

	newPostWithTrailersDecoded := func() *http.Request {
		return &http.Request{
			Method:        http.MethodPost,
			URL:           &url.URL{Path: "/hello.txt"},
			Host:          "www.example.com",
			ContentLength: -1,
			RequestURI:    "/hello.txt",
			Header:        http.Header{},
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          io.NopCloser(strings.NewReader("Hello world!")),
			Trailer: http.Header{
				"X-Test-1": []string{"foo", "bar"},
				"X-Test-2": []string{"baz"},
			},
		}
	}

	return map[string]requestRoundTripTest{
		"ok, RFC example, known length": {
			original: newRFCExampleOriginal,
			encoder:  newRFCExampleEncoder,
			wantEncoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
				const s = `00034745 54056874 74707300 0a2f6865
                           6c6c6f2e 74787440 6c0a7573 65722d61
                           67656e74 34637572 6c2f372e 31362e33
                           206c6962 6375726c 2f372e31 362e3320
                           4f70656e 53534c2f 302e392e 376c207a
                           6c69622f 312e322e 3304686f 73740f77
                           77772e65 78616d70 6c652e63 6f6d0f61
                           63636570 742d6c61 6e677561 67650665
                           6e2c206d 690000`

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			truncate: []int{
				1, // truncated trailer
				2, // truncated body and trailer
			},
			wantDecoded: func() *http.Request {
				return newRFCExampleDecoded(0)
			},
		},
		"ok, RFC example, indeterminate length": {
			original: newRFCExampleOriginal,
			encoder: func() *RequestEncoder {
				enc := newRFCExampleEncoder()
				enc.MapFunc = func(req *http.Request) (*Request, error) {
					// use rfc example encoder but encode as indeterminate length.
					r, err := newRFCExampleEncoder().MapFunc(req)
					if err != nil {
						return r, err
					}
					r.KnownLength = false
					r.ContentLength = -1
					return r, nil
				}
				// pad to a multiple
				enc.PadToMultipleOf = 16
				return enc
			},
			wantEncoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
				const s = `02034745 54056874 74707300 0a2f6865
		                   6c6c6f2e 7478740a 75736572 2d616765
		                   6e743463 75726c2f 372e3136 2e33206c
		                   69626375 726c2f37 2e31362e 33204f70
		                   656e5353 4c2f302e 392e376c 207a6c69
		                   622f312e 322e3304 686f7374 0f777777
		                   2e657861 6d706c65 2e636f6d 0f616363
		                   6570742d 6c616e67 75616765 06656e2c
		                   206d6900 00000000 00000000 00000000`

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			truncate: []int{
				1,  //     206d6900 00000000 00000000 0000000  # minus one byte of padding
				10, //     206d6900 0000                       # minus all padding
				11, //     206d6900 00                         # minus padding and trailer
				12, //     206d6900                            # minus padding, trailer and body
			},
			wantDecoded: func() *http.Request {
				return newRFCExampleDecoded(-1)
			},
		},
		"ok, RFC example, indeterminate length, minus padding": {
			original: newRFCExampleOriginal,
			encoder: func() *RequestEncoder {
				enc := newRFCExampleEncoder()
				enc.MapFunc = func(req *http.Request) (*Request, error) {
					// use rfc example encoder but encode as indeterminate length.
					r, err := newRFCExampleEncoder().MapFunc(req)
					if err != nil {
						return r, err
					}
					r.KnownLength = false
					r.ContentLength = -1
					return r, nil
				}
				return enc
			},
			wantEncoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
				const s = `02034745 54056874 74707300 0a2f6865
		                   6c6c6f2e 7478740a 75736572 2d616765
		                   6e743463 75726c2f 372e3136 2e33206c
		                   69626375 726c2f37 2e31362e 33204f70
		                   656e5353 4c2f302e 392e376c 207a6c69
		                   622f312e 322e3304 686f7374 0f777777
		                   2e657861 6d706c65 2e636f6d 0f616363
		                   6570742d 6c616e67 75616765 06656e2c
		                   206d6900 0000`

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			wantDecoded: func() *http.Request {
				return newRFCExampleDecoded(-1)
			},
		},
		"ok, POST with trailers, default encoder": {
			original:    newPostWithTrailerOriginal,
			wantEncoded: newPostWithTrailersIndetermininateLenEncoded,
			wantDecoded: newPostWithTrailersDecoded,
		},
		"ok, POST with trailers, known length encoder": {
			original: newPostWithTrailerOriginal,
			encoder: func() *RequestEncoder {
				return NewKnownLengthRequestEncoder()
			},
			wantEncoded: newPostWithTrailersKnownLenEncoded,
			wantDecoded: newPostWithTrailersDecoded,
		},
		"ok, POST with trailers, indeterminate length encoder": {
			original: newPostWithTrailerOriginal,
			encoder: func() *RequestEncoder {
				return NewIndeterminateLengthRequestEncoder()
			},
			wantEncoded: newPostWithTrailersIndetermininateLenEncoded,
			wantDecoded: newPostWithTrailersDecoded,
		},
	}
}

func TestEncodeDecodeRequestRoundTrip(t *testing.T) {
	test := newRequestTestCases()
	for name, tc := range test {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			enc := &RequestEncoder{}
			dec := &RequestDecoder{}
			if tc.encoder != nil {
				enc = tc.encoder()
			}
			if tc.decoder != nil {
				dec = tc.decoder()
			}

			msg, err := enc.EncodeRequest(tc.original())
			require.NoError(t, err)

			require.True(t, msg.IsRequest())
			require.False(t, msg.IsResponse())

			wantBytes := tc.wantEncoded()
			err = iotest.TestReader(msg, wantBytes)
			require.NoError(t, err)

			encReader := bytes.NewReader(wantBytes)
			got, err := dec.DecodeRequest(t.Context(), encReader)
			require.NoError(t, err)

			want := tc.wantDecoded().Clone(t.Context())
			requireEqualHTTPReqs(t, want, got)

			// verify the full reader was consumed during body reading, ensuring
			// no trailing padding bytes remain.
			require.Equal(t, 0, encReader.Len())

			// also test the truncated encodings.
			for _, truncate := range tc.truncate {
				truncatedBytes := wantBytes[:len(wantBytes)-truncate]

				got, err := dec.DecodeRequest(t.Context(), bytes.NewReader(truncatedBytes))
				require.NoError(t, err, truncate)

				want := tc.wantDecoded().Clone(t.Context())
				requireEqualHTTPReqs(t, want, got)
			}
		})
	}
}

func TestDecodeRequestFailures(t *testing.T) {
	tests := map[string]struct {
		encoded func() []byte
		wantErr func(t *testing.T, err error)
	}{
		"fail, RFC example with invalid framing indicator": {
			encoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
				const s = `04034745 54056874 74707300 0a2f6865
		                   6c6c6f2e 7478740a 75736572 2d616765
		                   6e743463 75726c2f 372e3136 2e33206c
		                   69626375 726c2f37 2e31362e 33204f70
		                   656e5353 4c2f302e 392e376c 207a6c69
		                   622f312e 322e3304 686f7374 0f777777
		                   2e657861 6d706c65 2e636f6d 0f616363
		                   6570742d 6c616e67 75616765 06656e2c
		                   206d6900 00000000 00000000 00000000`

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, RFC example, indeterminate length GET request, header section is missing terminator": {
			encoded: func() []byte {
				// taken from:
				// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-example
				const s = `02034745 54056874 74707300 0a2f6865
		                   6c6c6f2e 7478740a 75736572 2d616765
		                   6e743463 75726c2f 372e3136 2e33206c
		                   69626375 726c2f37 2e31362e 33204f70
		                   656e5353 4c2f302e 392e376c 207a6c69
		                   622f312e 322e3304 686f7374 0f777777
		                   2e657861 6d706c65 2e636f6d 0f616363
		                   6570742d 6c616e67 75616765 06656e2c
		                   206d69` // minus padding and 000000

				return must(hex.DecodeString(removeNonHexRunes(s)))
			},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			decoder := &RequestDecoder{}
			_, err := decoder.DecodeRequest(t.Context(), bytes.NewBuffer(tc.encoded()))
			tc.wantErr(t, err)
		})
	}
}

func removeNonHexRunes(s string) string {
	b := strings.Builder{}
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			_, err := b.WriteRune(r)
			if err != nil {
				panic("failed to write run on user provided string: " + err.Error())
			}
		}
	}
	return b.String()
}

// can't use test package because of import cycle issues.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type eofCallback struct {
	r        io.Reader
	callback func()
	called   bool
}

func (c *eofCallback) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil {
		if errors.Is(err, io.EOF) && !c.called {
			c.callback()
			c.called = true
		}
	}
	return n, err
}
