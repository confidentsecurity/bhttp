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
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderToFieldLines(t *testing.T) {
	tests := map[string]struct {
		h         http.Header
		header    bool
		trailer   bool
		want      []fieldLine   // used when wantOneOf is nil.
		wantOneOf [][]fieldLine // matches one of the sets of field lines.
	}{
		"ok, nil header": {
			h:       nil,
			header:  true,
			trailer: true,
			want:    nil,
		},
		"ok, empty header": {
			h:       http.Header{},
			header:  true,
			trailer: true,
			want:    nil,
		},
		"ok, key with nil slice": {
			h: http.Header{
				"k": nil,
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), nil},
			},
		},
		"ok, key with empty slice": {
			h: http.Header{
				"k": nil,
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), nil},
			},
		},
		"ok, key with empty string val": {
			h: http.Header{
				"k": []string{""},
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), []byte("")},
			},
		},
		"ok, key with multiple empty string vals": {
			h: http.Header{
				"k": []string{"", "", ""},
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), []byte("")},
				{[]byte("k"), []byte("")},
				{[]byte("k"), []byte("")},
			},
		},
		"ok, key with single val": {
			h: http.Header{
				"k": []string{"v"},
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), []byte("v")},
			},
		},
		"ok, key with multiple vals": {
			h: http.Header{
				"k": []string{"a", "b", "c"},
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("k"), []byte("a")},
				{[]byte("k"), []byte("b")},
				{[]byte("k"), []byte("c")},
			},
		},
		"ok, multiple keys with single vals": {
			h: http.Header{
				"k1": []string{"a"},
				"k2": []string{"b"},
			},
			header:  true,
			trailer: true,
			wantOneOf: [][]fieldLine{
				{
					{[]byte("k1"), []byte("a")},
					{[]byte("k2"), []byte("b")},
				},
				{
					{[]byte("k2"), []byte("b")},
					{[]byte("k1"), []byte("a")},
				},
			},
		},
		"ok, multiple keys with multiple vals": {
			h: http.Header{
				"k1": []string{"a", "b"},
				"k2": []string{"c", "d"},
			},
			header:  true,
			trailer: true,
			wantOneOf: [][]fieldLine{
				{
					{[]byte("k1"), []byte("a")},
					{[]byte("k1"), []byte("b")},
					{[]byte("k2"), []byte("c")},
					{[]byte("k2"), []byte("d")},
				},
				{
					{[]byte("k2"), []byte("c")},
					{[]byte("k2"), []byte("d")},
					{[]byte("k1"), []byte("a")},
					{[]byte("k1"), []byte("b")},
				},
			},
		},
		"ok, names are lowercased": {
			h: http.Header{
				"Accept-Encoding": []string{"text/json"},
			},
			header:  true,
			trailer: true,
			want: []fieldLine{
				{[]byte("accept-encoding"), []byte("text/json")},
			},
		},
		"ok, bad trailer headers are allowed in regular headers": {
			h: http.Header{
				"Content-Encoding": []string{"text/json"},
			},
			header:  true,
			trailer: false,
			want: []fieldLine{
				{[]byte("content-encoding"), []byte("text/json")},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.header {
				got, err := headerToFieldLines(tc.h, false)
				require.NoError(t, err)
				if tc.wantOneOf != nil {
					require.Contains(t, tc.wantOneOf, got)
				} else {
					require.Equal(t, tc.want, got)
				}
			}

			if tc.trailer {
				got, err := headerToFieldLines(tc.h, true)
				require.NoError(t, err)
				if tc.wantOneOf != nil {
					require.Contains(t, tc.wantOneOf, got)
				} else {
					require.Equal(t, tc.want, got)
				}
			}
		})
	}

	failTests := map[string]struct {
		failHeader  bool
		failTrailer bool
		h           http.Header
	}{
		"fail, disallowed pseudo-header :method": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":method": nil,
			},
		},
		"fail, disallowed pseudo-header :scheme": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":scheme": nil,
			},
		},
		"fail, disallowed pseudo-header :authority": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":authority": nil,
			},
		},
		"fail, disallowed pseudo-header :path": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":path": nil,
			},
		},
		"fail, disallowed pseudo-header :status": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":status": nil,
			},
		},
		"fail, other pseudo-headers": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				// strictly speaking the BHTTP spec allows this, but since we normally can't
				// create such requests with Go, we just error.
				":test": nil,
			},
		},
		"fail, invalid field name": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				":": nil,
			},
		},
		"fail, invalid field value": {
			failHeader:  true,
			failTrailer: true,
			h: http.Header{
				"k": []string{string([]byte{0xd})}, // carriage return
			},
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.failHeader {
				_, err := headerToFieldLines(tc.h, false)
				require.Error(t, err)
			}

			if tc.failTrailer {
				_, err := headerToFieldLines(tc.h, true)
				require.Error(t, err)
			}
		})
	}

}
