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
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

type readOp struct {
	pLen    int
	wantP   []byte
	wantN   int
	wantErr error
}

func requireReadOps(t *testing.T, readOps []readOp, r io.Reader) {
	t.Helper()

	for _, op := range readOps {
		requireReadOp(t, op, r)
	}
}

func requireReadOp(t *testing.T, op readOp, r io.Reader) {
	p := make([]byte, op.pLen)
	n, err := r.Read(p)
	require.Equal(t, op.wantP, p[:n])
	require.Equal(t, op.wantN, n)
	require.Equal(t, op.wantErr, err)
}

func TestFixedLenReader(t *testing.T) {
	tests := map[string]struct {
		length  uint64
		r       io.Reader
		readOps []readOp
	}{
		"ok, 0 length, 0 byte read": {
			length: 0,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF}, // ensure consistent EOF.
			},
		},
		"ok, 0 length, 1 byte read": {
			length: 0,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 0 length, 1 byte read, 1 byte data": {
			length: 0,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 length, 0 byte read followed by 1 byte read": {
			length: 1,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{1, []byte{'a'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 length, 2 byte read": {
			length: 1,
			r:      strings.NewReader("a"),
			readOps: []readOp{
				{2, []byte{'a'}, 1, nil},
				{2, []byte{}, 0, io.EOF},
				{2, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 length, 1 byte read, 2 byte data": {
			length: 1,
			r:      strings.NewReader("aa"),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"fail, 1 length, 1 byte read, 0 byte data": {
			length: 1,
			r:      strings.NewReader(""),
			readOps: []readOp{
				{1, []byte{}, 0, io.ErrUnexpectedEOF},
				{1, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"ok, 8 length, 1 byte read": {
			length: 8,
			r:      strings.NewReader("abcdefgh"),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				{1, []byte{'b'}, 1, nil},
				{1, []byte{'c'}, 1, nil},
				{1, []byte{'d'}, 1, nil},
				{1, []byte{'e'}, 1, nil},
				{1, []byte{'f'}, 1, nil},
				{1, []byte{'g'}, 1, nil},
				{1, []byte{'h'}, 1, nil},
				{1, []byte{}, 0, io.EOF},
				{1, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 length, 4 byte read": {
			length: 8,
			r:      strings.NewReader("abcdefgh"),
			readOps: []readOp{
				{4, []byte{'a', 'b', 'c', 'd'}, 4, nil},
				{4, []byte{'e', 'f', 'g', 'h'}, 4, nil},
				{4, []byte{}, 0, io.EOF},
				{4, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 length, 8 byte read": {
			length: 8,
			r:      strings.NewReader("abcdefgh"),
			readOps: []readOp{
				{8, []byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}, 8, nil},
				{8, []byte{}, 0, io.EOF},
				{8, []byte{}, 0, io.EOF},
			},
		},
		"ok, 8 length, 4 byte read, 1 byte data reads": {
			length: 8,
			r:      iotest.OneByteReader(strings.NewReader("abcdefgh")),
			readOps: []readOp{
				{4, []byte{'a'}, 1, nil},
				{4, []byte{'b'}, 1, nil},
				{4, []byte{'c'}, 1, nil},
				{4, []byte{'d'}, 1, nil},
				{4, []byte{'e'}, 1, nil},
				{4, []byte{'f'}, 1, nil},
				{4, []byte{'g'}, 1, nil},
				{4, []byte{'h'}, 1, nil},
				{4, []byte{}, 0, io.EOF},
				{4, []byte{}, 0, io.EOF},
			},
		},
		"fail, 8 length, 1 byte read, 6 byte data": {
			length: 8,
			r:      strings.NewReader("abcdef"),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				{1, []byte{'b'}, 1, nil},
				{1, []byte{'c'}, 1, nil},
				{1, []byte{'d'}, 1, nil},
				{1, []byte{'e'}, 1, nil},
				{1, []byte{'f'}, 1, nil},
				{1, []byte{}, 0, io.ErrUnexpectedEOF},
				{1, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"fail, 8 length, 4 byte read, 6 byte data": {
			length: 8,
			r:      strings.NewReader("abcdef"),
			readOps: []readOp{
				{4, []byte{'a', 'b', 'c', 'd'}, 4, nil},
				{4, []byte{'e', 'f'}, 2, nil},
				{4, []byte{}, 0, io.ErrUnexpectedEOF},
				{4, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"fail, 8 length, 4 byte read, 6 byte data, eof together with final data": {
			length: 8,
			r:      iotest.DataErrReader(strings.NewReader("abcdef")),
			readOps: []readOp{
				{4, []byte{'a', 'b', 'c', 'd'}, 4, nil},
				{4, []byte{'e', 'f'}, 2, io.ErrUnexpectedEOF},
				{4, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newFixedLenReader(tc.length, tc.r)
			requireReadOps(t, tc.readOps, r)
		})
	}
}

// newTryReadBoundaryReadOp encodes TryReadBoundary call expectations into a readOp. Can be used
// together with requireReadOpsBounded to run readOps against a boundedReader.
func newTryReadBoundaryReadOp(want bool, wantErr error) readOp {
	op := readOp{
		pLen:    -1,
		wantErr: wantErr,
	}
	if want {
		op.wantN = 1
	} else {
		op.wantN = 0
	}
	return op
}

func requireTryReadBoundary(t *testing.T, want bool, wantErr error, r boundedReader) {
	t.Helper()

	got, err := r.TryReadBoundary()
	require.Equal(t, want, got)
	require.Equal(t, wantErr, err)
}

func requireReadOpsBounded(t *testing.T, readOps []readOp, r boundedReader) {
	t.Helper()

	for _, op := range readOps {
		if op.pLen == -1 {
			requireTryReadBoundary(t, op.wantN == 1, op.wantErr, r)
		} else {
			requireReadOp(t, op, r)
		}
	}
}

func TestZeroTerminatedReader(t *testing.T) {
	tests := map[string]struct {
		r          io.Reader
		readOps    []readOp
		verifyOrig func(r io.Reader)
	}{
		"ok, 1-byte terminator on first try": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator after 1 zero len read": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator after 3 zero len reads": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, boundary already read, returns false": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				newTryReadBoundaryReadOp(false, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				newTryReadBoundaryReadOp(false, nil),
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator on first try, trailing data": {
			r: bytes.NewReader([]byte{0x00, 'a'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'a'})
			},
		},
		"ok, 8-byte terminator on first try, trailing data": {
			r: bytes.NewReader([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'a'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'a'}) // verify trailing data is left untouched.
			},
		},
		"ok, 1-byte terminator on first try, 1 byte read before": {
			r: bytes.NewReader([]byte{'a', 0x00}),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator on first try, 1 byte read before, trailing data": {
			r: bytes.NewReader([]byte{'a', 0x00, 'b'}),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'b'}) // verify trailing data is left untouched.
			},
		},
		"ok, 1 byte terminator on first try, 1 byte terminator before, 1 byte trailing terminator": {
			r: bytes.NewReader([]byte{0x00, 0x00, 0x00}),
			readOps: []readOp{
				{1, []byte{0x00}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{0x00}) // verify trailing data is left untouched.
			},
		},
		"ok, 8-byte terminator on first try, 1 byte read before, trailing data": {
			r: bytes.NewReader([]byte{'a', 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'b'}),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'b'}) // verify trailing data is left untouched.
			},
		},
		"ok, 1-byte terminator on second try, 1 byte read inbetween": {
			r: bytes.NewReader([]byte{'a', 0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator on second try, 4 byte read inbetween": {
			r: bytes.NewReader([]byte{'a', 'b', 'c', 'd', 0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{4, []byte{'a', 'b', 'c', 'd'}, 4, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1-byte terminator on fifth try, 1 byte reads inbetween, trailing data": {
			r: bytes.NewReader([]byte{'a', 'b', 'c', 'd', 0x00, 'f'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'b'}, 1, nil},
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'c'}, 1, nil},
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'d'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'f'}) // verify trailing data is left untouched.
			},
		},
		"ok, 4-byte terminator on second try, severals reads inbetween, trailing data": {
			r: bytes.NewReader([]byte{'a', 'b', 'c', 'd', 'e', 'f', 0x80, 0x00, 0x00, 0x00, 'g', 'h', 'j'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{2, []byte{'a', 'b'}, 2, nil},
				{1, []byte{'c'}, 1, nil},
				{3, []byte{'d', 'e', 'f'}, 3, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'g', 'h', 'j'}) // verify trailing data is left untouched.
			},
		},
		"ok, original reader is a one byte reader": {
			r: iotest.OneByteReader(bytes.NewReader([]byte{'a', 'b', 'c', 0x80, 0x00, 0x00, 0x00, 'g', 'h', 'j'})),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{3, []byte{'a', 'b', 'c'}, 3, nil}, // stored in buffer
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte{'g', 'h', 'j'}) // verify trailing data is left untouched.
			},
		},
		"fail, original reader returns eof with terminator": {
			r: iotest.DataErrReader(bytes.NewReader([]byte{0x00})),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, io.ErrUnexpectedEOF),
				{0, []byte{}, 0, io.ErrUnexpectedEOF}, // follow up reads should return io.ErrUnexpectedEOF
			},
		},
		"fail, immediate eof during try": {
			r: bytes.NewReader([]byte{}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, io.ErrUnexpectedEOF),
				{0, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"fail, eof when reading data": {
			r: bytes.NewReader([]byte{'a', 'b'}),
			readOps: []readOp{
				{4, []byte{'a', 'b'}, 2, nil},
				{4, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"fail, unexpected eof but read some data from buffer": {
			r: bytes.NewReader([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}), // last 0x01 makes it not a zero.
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{9, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 8, io.ErrUnexpectedEOF},
			},
		},
		"fail, read terminator using normal read": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				{1, []byte{0x00}, 1, nil},
				newTryReadBoundaryReadOp(false, io.ErrUnexpectedEOF),
			},
		},
		"fail, eof while reading multi-byte terminator": {
			r: bytes.NewReader([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}), // missing last byte
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, io.ErrUnexpectedEOF),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newZeroTerminatedReader(tc.r)
			requireReadOpsBounded(t, tc.readOps, r)
			if tc.verifyOrig != nil {
				tc.verifyOrig(tc.r)
			}
		})
	}
}

func TestLenPrefixedReader(t *testing.T) {
	tests := map[string]struct {
		r          io.Reader
		readOps    []readOp
		verifyOrig func(r io.Reader)
	}{
		"ok, 1 byte zero length, boundary on first try": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte zero length, boundary on first try, after zero length reads": {
			r: bytes.NewReader([]byte{0x00}),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				{0, []byte{}, 0, nil},
				newTryReadBoundaryReadOp(true, nil),
				newTryReadBoundaryReadOp(false, nil), // follow up should return false
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte zero length, with trailing data": {
			r: bytes.NewReader([]byte{0x00, 'a'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF}, // follow up reads should return io.EOF
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte("a"))
			},
		},
		"ok, 4 byte zero length, boundary on first try, after zero length reads": {
			r: bytes.NewReader([]byte{0x80, 0x00, 0x00, 0x00}),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 4 byte zero length, with trailing data": {
			r: bytes.NewReader([]byte{0x80, 0x00, 0x00, 0x00, 'a'}),
			readOps: []readOp{
				{0, []byte{}, 0, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte("a"))
			},
		},
		"ok, 1 byte length, single read, boundary on first try": {
			r: bytes.NewReader([]byte{1, 'a'}),
			readOps: []readOp{
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte length, single read, boundary on second try": {
			r: bytes.NewReader([]byte{1, 'a'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'a'}, 1, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte length, multiple reads, boundary on second try": {
			r: bytes.NewReader([]byte{3, 'a', 'b', 'c'}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, nil),
				{1, []byte{'a'}, 1, nil},
				{2, []byte{'b', 'c'}, 2, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
		},
		"ok, 1 byte length, trailing data": {
			r: bytes.NewReader([]byte{3, 'a', 'b', 'c', 'd'}),
			readOps: []readOp{
				{3, []byte{'a', 'b', 'c'}, 3, nil},
				newTryReadBoundaryReadOp(true, nil),
				{0, []byte{}, 0, io.EOF},
				{0, []byte{}, 0, io.EOF},
			},
			verifyOrig: func(r io.Reader) {
				requireReadAll(t, r, []byte("d"))
			},
		},
		"fail, eof in length via normal read": {
			r: bytes.NewReader([]byte{0x80, 0x00}),
			readOps: []readOp{
				{0, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
		"fail, eof in length via try": {
			r: bytes.NewReader([]byte{0x80, 0x00}),
			readOps: []readOp{
				newTryReadBoundaryReadOp(false, io.ErrUnexpectedEOF),
			},
		},
		"fail, eof in data": {
			r: bytes.NewReader([]byte{3, 'a', 'b'}),
			readOps: []readOp{
				{3, []byte{'a', 'b'}, 2, nil},
				{3, []byte{}, 0, io.ErrUnexpectedEOF},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newLenPrefixedReader(tc.r)
			requireReadOpsBounded(t, tc.readOps, r)
			if tc.verifyOrig != nil {
				tc.verifyOrig(tc.r)
			}
		})
	}
}

func requireReadAll(t *testing.T, r io.Reader, want []byte) {
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
