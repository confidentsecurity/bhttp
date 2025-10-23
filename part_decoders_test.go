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
	"net/http"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestFieldSectionDecoder(t *testing.T) {
	tests := map[string]struct {
		maxSectionLen        uint64
		isTrailer            bool
		b                    func() []byte
		want                 http.Header
		wantErr              func(t *testing.T, err error) // only used if non-nil.
		makeKnownLen         func(b []byte) []byte         // defaults to prefixing with b len if nil
		makeIndeterminateLen func(b []byte) []byte         // defaults to postfixing with 0 if nil.
	}{
		"ok, 0 field lines": {
			maxSectionLen: 0,
			b: func() []byte {
				return []byte{}
			},
			want: http.Header{},
		},
		"ok, 1 field line, minimal": {
			maxSectionLen: 3,
			b: func() []byte {
				return []byte{1, 'h', 0}
			},
			want: http.Header{
				"H": []string{""},
			},
		},
		"ok, under section max lengths": {
			// most other cases match max length exactly to content length,
			// so this one explicitly verifies we can have content under the max length.
			maxSectionLen: 4,
			b: func() []byte {
				return []byte{1, 'h', 0}
			},
			want: http.Header{
				"H": []string{""},
			},
		},
		"ok, 2 field lines, minimal, same header": {
			maxSectionLen: 6,
			b: func() []byte {
				return []byte{
					1, 'h', 0,
					1, 'h', 0,
				}
			},
			want: http.Header{
				"H": []string{"", ""},
			},
		},
		"ok, 2 field lines, minimal, different headers": {
			maxSectionLen: 6,
			b: func() []byte {
				return []byte{
					1, 'h', 0,
					1, 'j', 0,
				}
			},
			want: http.Header{
				"H": []string{""},
				"J": []string{""},
			},
		},
		"ok, 1 field line, single-byte value": {
			maxSectionLen: 4,
			b: func() []byte {
				return []byte{
					1, 'h', 1, 'a',
				}
			},
			want: http.Header{
				"H": []string{"a"},
			},
		},
		"ok, 1 field line, multi-byte name and value": {
			maxSectionLen: 8,
			b: func() []byte {
				return []byte{
					3, 'h', 'd', 'r', 3, 'a', 'b', 'c',
				}
			},
			want: http.Header{
				"Hdr": []string{"abc"},
			},
		},
		"ok, 2 field lines, comma separated values are not normalized": {
			// this is the same as what Go net/http does. See:
			// https://github.com/golang/go/issues/62471
			maxSectionLen: 10,
			b: func() []byte {
				return []byte{
					1, 'h', 3, 'a', ',', 'b',
					1, 'h', 1, 'c',
				}
			},
			want: http.Header{
				"H": []string{"a,b", "c"},
			},
		},
		"ok, 4 field lines, multiple values for single header, order of values is preserved": {
			maxSectionLen: 18,
			b: func() []byte {
				return []byte{
					1, 'h', 2, 'a', 'b',
					1, 'h', 3, 'c', 'd', 'e',
					1, 'h', 0,
					1, 'h', 1, 'f',
				}
			},
			want: http.Header{
				"H": []string{"ab", "cde", "", "f"},
			},
		},
		"ok, 4 field lines, multiple values for multiple headers, order of values is preserved": {
			maxSectionLen: 18,
			b: func() []byte {
				return []byte{
					1, 'h', 2, 'a', 'b',
					1, 'h', 3, 'c', 'd', 'e',
					1, 'j', 0,
					1, 'j', 1, 'f',
				}
			},
			want: http.Header{
				"H": []string{"ab", "cde"},
				"J": []string{"", "f"},
			},
		},
		"ok, 4 field lines, multiple values for multiple headers, interwoven, order of values is preserved": {
			maxSectionLen: 18,
			b: func() []byte {
				return []byte{
					1, 'h', 2, 'a', 'b',
					1, 'j', 0,
					1, 'h', 3, 'c', 'd', 'e',
					1, 'j', 1, 'f',
				}
			},
			want: http.Header{
				"H": []string{"ab", "cde"},
				"J": []string{"", "f"},
			},
		},
		"ok, 1 field line, names and value of multi-byte length": {
			maxSectionLen: uint64(quicvarint.Len(128)) + 128 + uint64(quicvarint.Len(256)) + 256,
			b: func() []byte {
				b := []byte{}
				b = quicvarint.Append(b, 128)
				b = append(b, bytes.Repeat([]byte("h"), 128)...)
				b = quicvarint.Append(b, 256)
				b = append(b, bytes.Repeat([]byte("a"), 256)...)
				return b
			},
			want: http.Header{
				"H" + strings.Repeat("h", 128-1): []string{strings.Repeat("a", 256)},
			},
		},
		"ok, real world case": {
			maxSectionLen: 4096,
			b: func() []byte {
				b := []byte{}
				b = quicvarint.Append(b, 4)
				b = append(b, []byte("Host")...)
				b = quicvarint.Append(b, 9)
				b = append(b, []byte("127.0.0.1")...)
				b = quicvarint.Append(b, 12)
				b = append(b, []byte("Content-Type")...)
				b = quicvarint.Append(b, 10)
				b = append(b, []byte("text/plain")...)
				b = quicvarint.Append(b, 37)
				b = append(b, []byte("X-Confsec-Test-Data-With-Extra-Length")...)
				b = quicvarint.Append(b, 256)
				b = append(b, bytes.Repeat([]byte("a"), 256)...)
				b = quicvarint.Append(b, 15)
				b = append(b, []byte("Accept-Encoding")...)
				b = quicvarint.Append(b, 4)
				b = append(b, []byte("gzip")...)
				b = quicvarint.Append(b, 15)
				b = append(b, []byte("Accept-Encoding")...)
				b = quicvarint.Append(b, 7)
				b = append(b, []byte("deflate")...)
				return b
			},
			want: http.Header{
				"Host":                                  []string{"127.0.0.1"},
				"Content-Type":                          []string{"text/plain"},
				"X-Confsec-Test-Data-With-Extra-Length": []string{strings.Repeat("a", 256)},
				"Accept-Encoding":                       []string{"gzip", "deflate"},
			},
		},
		"ok, custom pseudo header without value is skipped": {
			maxSectionLen: 4,
			b: func() []byte {
				return []byte{
					2, ':', 'h', 0,
				}
			},
			want: http.Header{},
		},
		"ok, custom pseudo header with value is skipped": {
			maxSectionLen: 5,
			b: func() []byte {
				return []byte{
					2, ':', 'h', 1, 'a',
				}
			},
			want: http.Header{},
		},
		"ok, skipping pseudo-headers does not affect other headers": {
			maxSectionLen: 18,
			b: func() []byte {
				return []byte{
					2, ':', 'h', 1, 'a',
					2, ':', 'j', 1, 'b',
					1, 'h', 1, 'c',
					1, 'j', 1, 'd',
				}
			},
			want: http.Header{
				"H": []string{"c"},
				"J": []string{"d"},
			},
		},
		"fail, 0 max section length violated": {
			maxSectionLen: 0,
			b: func() []byte {
				return []byte{
					1, 'h', 0,
				}
			},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, ErrTooMuchData)
			},
		},
		"fail, invalid max section length": {
			maxSectionLen: 2, // the minimum length of a non-zero section is 3.
			b: func() []byte {
				return []byte{
					1, 'h', 0,
				}
			},
			wantErr: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		"fail, max section length violated": {
			maxSectionLen: 3,
			b: func() []byte {
				return []byte{
					1, 'h', 1, 'a',
				}
			},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, ErrTooMuchData)
			},
		},
		// TODO: can't be distiniguished from section end in non-determinate length encoding.
		//"fail, 0 byte field line name": {
		//	maxSectionLen: 3,
		//	b: func() []byte {
		//		return []byte{
		//			0, 0,
		//		}
		//	},
		//	wantErr: func(t *testing.T, err error) {
		//		test.RequireEqualErrorAs(t, &LimitViolationError{
		//			Name:  "field line name",
		//			Min:   1,
		//			Max:   1, // remaining after reading the field line name length.
		//			Value: 0,
		//		}, err)
		//	},
		//},
		"fail, field line name extends beyond max section length": {
			maxSectionLen: 3,
			b: func() []byte {
				return []byte{
					3, 'h', 0, // 3 byte section length
				}
			},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, ErrTooMuchData)
			},
		},
		"fail, field line value extends beyond max section length": {
			maxSectionLen: 3,
			b: func() []byte {
				return []byte{
					1, 'h', 1, // would expect this to be a 5 byte section
				}
			},
			wantErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, ErrTooMuchData)
			},
		},
		"fail, pseudo header in trailers": {
			maxSectionLen: 4,
			isTrailer:     true,
			b: func() []byte {
				return []byte{
					2, ':', 'h', 0,
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, unreserved pseudo header after regular header": {
			maxSectionLen: 7,
			b: func() []byte {
				return []byte{
					1, 'h', 0,
					2, ':', 'h', 0,
				}
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
		"fail, disallowed header in trailers": {
			maxSectionLen: 15,
			isTrailer:     true,
			b: func() []byte {
				b := []byte{}
				b = quicvarint.Append(b, 13)
				b = append(b, []byte("Authorization")...)
				b = quicvarint.Append(b, 0)
				return b
			},
			wantErr: func(t *testing.T, err error) {
				invalidMsgErr := InvalidMessageError{}
				require.ErrorAs(t, err, &invalidMsgErr)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name+", known length", func(t *testing.T) {
			t.Parallel()

			dec := &fieldSectionDecoder{
				maxSectionLen: tc.maxSectionLen,
				isTrailer:     tc.isTrailer,
			}

			encLines := tc.b()
			b := append(quicvarint.Append(nil, uint64(len(encLines))), encLines...)

			buf := bytes.NewBuffer(nil)
			got, err := dec.decode(buf, bytes.NewReader(b), true)
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})

		t.Run(name+", indeterminate length", func(t *testing.T) {
			t.Parallel()

			dec := &fieldSectionDecoder{
				maxSectionLen: tc.maxSectionLen,
				isTrailer:     tc.isTrailer,
			}

			// turn into a indeterminate length section by postfixing with a 0.
			buf := bytes.NewBuffer(nil)
			got, err := dec.decode(buf, bytes.NewReader(append(tc.b(), 0)), false)
			if tc.wantErr != nil {
				tc.wantErr(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	// invalidFieldLineNames are names that should always error.
	invalidFieldLineNames := []string{
		// valid mime characters, but invalid http header names
		"{a}",
		// reserved pseudo-headers
		":method",
		":scheme",
		":authority",
		":path",
		":status",
		// attempt to circumvent disallowed names
		`\:method`,
		":Method",
		":METHOD",
		" :method ",
		": method",
		// non-ascii names
		"🫠",
	}

	for _, name := range invalidFieldLineNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dec := &fieldSectionDecoder{
				maxSectionLen: 1024,
			}

			// turn into a indeterminate length section by postfixing with a 0.
			b := []byte{}
			b = append(b, quicvarint.Append(nil, uint64(len(name)))...)
			b = append(b, []byte(name)...)
			b = append(b, 0) // field line value length
			b = append(b, 0) // section terminator
			buf := bytes.NewBuffer(nil)
			_, err := dec.decode(buf, bytes.NewReader(b), false)
			invalidMsgErr := InvalidMessageError{}
			require.ErrorAs(t, err, &invalidMsgErr)
		})
	}
}
