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
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodedInt(t *testing.T) {
	tests := map[string]struct {
		n       uint64
		wantLen int
		readOps []readOp
	}{
		"1 byte result, 0 byte read": {
			n:       0,
			wantLen: 1,
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
			},
		},
		"1 byte result, 1 byte read": {
			n:       0,
			wantLen: 1,
			readOps: []readOp{
				{1, []byte{0}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF}, // ensure consistent EOF.
			},
		},
		"1 byte result, 2 byte read": {
			n:       0,
			wantLen: 1,
			readOps: []readOp{
				{2, []byte{0}, 1, nil},
				{2, []byte{}, 0, io.EOF},
				{2, []byte{}, 0, io.EOF},
			},
		},
		"8 byte result, 0 byte read": {
			n:       151288809941952652,
			wantLen: 8,
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
			},
		},
		"8 byte result, 1 byte read": {
			n:       151288809941952652,
			wantLen: 8,
			readOps: []readOp{
				{1, []byte{0b11000010}, 1, nil},
				{1, []byte{0x19}, 1, nil},
				{1, []byte{0x7c}, 1, nil},
				{1, []byte{0x5e}, 1, nil},
				{1, []byte{0xff}, 1, nil},
				{1, []byte{0x14}, 1, nil},
				{1, []byte{0xe8}, 1, nil},
				{1, []byte{0x8c}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"8 byte result, 4 byte read": {
			n:       151288809941952652,
			wantLen: 8,
			readOps: []readOp{
				{4, []byte{0b11000010, 0x19, 0x7c, 0x5e}, 4, nil},
				{4, []byte{0xff, 0x14, 0xe8, 0x8c}, 4, nil},
				{4, []byte{}, 0, io.EOF},
				{4, []byte{}, 0, io.EOF},
			},
		},
		"8 byte result, 8 byte read": {
			n:       151288809941952652,
			wantLen: 8,
			readOps: []readOp{
				{8, []byte{0b11000010, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 8, nil},
				{8, []byte{}, 0, io.EOF},
				{8, []byte{}, 0, io.EOF},
			},
		},
		"8 byte result, 9 byte read": {
			n:       151288809941952652,
			wantLen: 8,
			readOps: []readOp{
				{9, []byte{0b11000010, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 8, nil},
				{9, []byte{}, 0, io.EOF},
				{9, []byte{}, 0, io.EOF},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			buf := bytes.NewBuffer(nil)
			r, gotLen := newEncodedInt(buf, tc.n)
			require.Equal(t, tc.wantLen, gotLen)
			requireReadOps(t, tc.readOps, r)
		})
	}

	t.Run("fail, non-quic encodable integer", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		r, gotLen := newEncodedInt(buf, uint64(math.MaxUint))
		require.Equal(t, 0, gotLen)

		p := make([]byte, 10)
		n, err := r.Read(p)
		require.Equal(t, 0, n)
		require.Error(t, err)
	})
}

func TestLenPrefixedData(t *testing.T) {
	tests := map[string]struct {
		length  uint64
		data    io.Reader
		wantLen uint64
		readOps []readOp
	}{
		"ok, 1 byte result, 0 byte read, 0 byte data": {
			length:  0,
			data:    strings.NewReader(""),
			wantLen: 1,
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
			},
		},
		"ok, 1 byte result, 1 byte read, 0 byte data": {
			length:  0,
			data:    strings.NewReader(""),
			wantLen: 1,
			readOps: []readOp{
				{1, []byte{0}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte result, 2 byte read, 0 byte data": {
			length:  0,
			data:    strings.NewReader(""),
			wantLen: 1,
			readOps: []readOp{
				{2, []byte{0}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 2 byte result, 1 byte reads, 1 byte data": {
			length:  1,
			data:    strings.NewReader("a"),
			wantLen: 2,
			readOps: []readOp{
				{1, []byte{1}, 1, nil},
				{1, []byte{'a'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 2 byte result, 2 byte reads, 1 byte data": {
			length:  1,
			data:    strings.NewReader("a"),
			wantLen: 2,
			readOps: []readOp{
				{2, []byte{1}, 1, nil},
				{2, []byte{'a'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 byte result, 1 byte reads, 7 byte data": {
			length:  7,
			data:    strings.NewReader("abcdefg"),
			wantLen: 8,
			readOps: []readOp{
				{1, []byte{7}, 1, nil},
				{1, []byte{'a'}, 1, nil},
				{1, []byte{'b'}, 1, nil},
				{1, []byte{'c'}, 1, nil},
				{1, []byte{'d'}, 1, nil},
				{1, []byte{'e'}, 1, nil},
				{1, []byte{'f'}, 1, nil},
				{1, []byte{'g'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 byte result, 4 byte reads, 7 byte data": {
			length:  7,
			data:    strings.NewReader("abcdefg"),
			wantLen: 8,
			readOps: []readOp{
				{4, []byte{7}, 1, nil},
				{4, []byte{'a', 'b', 'c', 'd'}, 4, nil},
				{4, []byte{'e', 'f', 'g'}, 3, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 byte result, 8 byte reads, 7 byte data": {
			length:  7,
			data:    strings.NewReader("abcdefg"),
			wantLen: 8,
			readOps: []readOp{
				{8, []byte{7}, 1, nil},
				{8, []byte{'a', 'b', 'c', 'd', 'e', 'f', 'g'}, 7, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			buf := bytes.NewBuffer(nil)
			r, gotLen := newLenPrefixedData(buf, tc.length, tc.data)
			require.Equal(t, tc.wantLen, gotLen)
			requireReadOps(t, tc.readOps, r)
		})
	}
}

func TestEncodedContentChunks(t *testing.T) {
	tests := map[string]struct {
		bufCap  int
		r       io.Reader
		readOps []readOp
	}{
		"ok, 0 byte reads, no data": {
			bufCap: 2,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte reads, no data": {
			bufCap: 2,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 0 byte reads, with data": {
			bufCap: 2,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
			},
		},
		"ok, 1 byte reads, 1 byte data, 2 byte chunk over 2 reads": {
			bufCap: 2,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{1, []byte{1}, 1, nil},
				{1, []byte{'a'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte reads, 3 byte data, 2 byte chunks over 6 reads": {
			bufCap: 2,
			r:      strings.NewReader("abc"),
			readOps: []readOp{
				{1, []byte{1}, 1, nil},
				{1, []byte{'a'}, 1, nil},
				{1, []byte{1}, 1, nil},
				{1, []byte{'b'}, 1, nil},
				{1, []byte{1}, 1, nil},
				{1, []byte{'c'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 2 byte reads, 1 byte data, 2 byte chunk over 1 read": {
			bufCap: 2,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{2, []byte{1, 'a'}, 2, nil},
				{2, []byte{}, 0, io.EOF},
				{2, []byte{}, 0, io.EOF},
			},
		},
		"ok, 2 byte reads, 3 byte data, 2 byte chunks over 3 reads": {
			bufCap: 2,
			r:      strings.NewReader("abc"),
			readOps: []readOp{
				{2, []byte{1, 'a'}, 2, nil},
				{2, []byte{1, 'b'}, 2, nil},
				{2, []byte{1, 'c'}, 2, nil},
				{2, []byte{}, 0, io.EOF},
				{2, []byte{}, 0, io.EOF},
			},
		},
		"ok, 2 byte reads, 3 byte data, 3 byte chunks over 2 reads": {
			bufCap: 3,
			r:      strings.NewReader("abc"),
			readOps: []readOp{
				{2, []byte{2, 'a'}, 2, nil},
				{2, []byte{'b'}, 1, nil},
				{2, []byte{1, 'c'}, 2, nil},
				{2, []byte{}, 0, io.EOF},
				{2, []byte{}, 0, io.EOF},
			},
		},
		"ok, 3 byte reads, 3 byte data, 3 byte chunks over 2 reads": {
			bufCap: 3,
			r:      strings.NewReader("abc"),
			readOps: []readOp{
				{3, []byte{2, 'a', 'b'}, 3, nil},
				{3, []byte{1, 'c'}, 2, nil},
				{3, []byte{}, 0, io.EOF},
				{3, []byte{}, 0, io.EOF},
			},
		},
		"ok, 4 byte reads, 3 byte data, 3 byte chunks over 2 reads": {
			bufCap: 3,
			r:      strings.NewReader("abc"),
			readOps: []readOp{
				{4, []byte{2, 'a', 'b'}, 3, nil},
				{4, []byte{1, 'c'}, 2, nil},
				{4, []byte{}, 0, io.EOF},
				{4, []byte{}, 0, io.EOF},
			},
		},
		"fail, not enough bufCap": {
			bufCap: 1,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{0, []byte{}, 0, fmt.Errorf("buffer should be at least two bytes, got %d", 1)},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			buf := bytes.NewBuffer(make([]byte, 0, tc.bufCap))
			r := newEncodedContentChunks(buf, tc.r)
			requireReadOps(t, tc.readOps, r)
		})
	}
}
