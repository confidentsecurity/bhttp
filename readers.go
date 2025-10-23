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
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// fixedLenReader will read N bytes from the underlying reader before returning
// io.EOF. If an io.EOF is encountered before N bytes are read, fixedLenReader will
// return [io.ErrUnexpectedEOF].
type fixedLenReader struct {
	remaining uint64
	r         io.Reader
}

func newFixedLenReader(n uint64, r io.Reader) *fixedLenReader {
	return &fixedLenReader{
		remaining: n,
		r:         r,
	}
}

func (r *fixedLenReader) Remaining() uint64 {
	return r.remaining
}

func (r *fixedLenReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	if uint64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}

	n, err := r.r.Read(p)
	r.remaining -= uint64(n) // #nosec G115 -- read is non-negative
	if errors.Is(err, io.EOF) && r.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// ReadRemaining reads the remaining data into a new buffer. It is up to the caller
// to ensure that this doesn't allocate an excessively large buffer.
func (r *fixedLenReader) ReadRemaining() ([]byte, int, error) {
	b := make([]byte, r.Remaining())
	n, err := io.ReadFull(r, b)
	return b, n, err
}

// boundedReader is a reader with a clearly defined boundary. This boundary might
// need to be read from the underlying data stream. Read should only return io.EOF
// after TryReadBoundary has returned true.
//
// If Read encounters an io.EOF from the underlying data stream before
// TryReadBoundary has returned true it will return io.ErrUnexpectedEOF instead.
type boundedReader interface {
	io.Reader
	TryReadBoundary() (bool, error)
}

// zeroTerminatedReader is a [boundedReader] which is terminated by a quic-encoded
// zero in the underlying data stream. This reader will begin returning io.EOF after
// such a zero is read during a call to TryReadBoundary.
type zeroTerminatedReader struct {
	r       io.Reader
	readBuf *bytes.Buffer
	decBuf  *bytes.Buffer
	eof     bool
}

func newZeroTerminatedReader(r io.Reader) boundedReader {
	buf1 := make([]byte, 0, 8)
	buf2 := make([]byte, 0, 8)
	return &zeroTerminatedReader{
		r:       r,
		readBuf: bytes.NewBuffer(buf1),
		decBuf:  bytes.NewBuffer(buf2),
		eof:     false,
	}
}

func (r *zeroTerminatedReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	var (
		bn  int
		err error
	)
	if r.readBuf != nil && r.readBuf.Len() > 0 {
		bn, err = r.readBuf.Read(p)
		if err != nil && !errors.Is(err, io.EOF) {
			return bn, err
		}
		if len(p) == bn {
			return bn, nil
		}

		p = p[bn:]
	}

	rn, err := r.r.Read(p)
	if err != nil && errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return rn + bn, err
}

func (r *zeroTerminatedReader) TryReadBoundary() (bool, error) {
	if r.eof {
		return false, nil
	}

	// we need to keep track of the data being read as it's decoded,
	// since we don't know for sure if this data will actually contain
	// the boundary. We'll read into decBuf via a TeeReader.
	r.decBuf.Reset()
	teeR := io.TeeReader(r, r.decBuf)

	quicreader := quicvarint.NewReader(teeR)
	x, err := quicvarint.Read(quicreader)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		// Note: we're reading from ourselves here, so any io.EOF
		// will already be turned into io.ErrUnexpectedEOF.
		return false, io.ErrUnexpectedEOF
	}

	r.eof = err == nil && x == 0
	if !r.eof {
		// We didn't read the terminator. We need to make the read data
		// available in Read by swapping the buffers.
		r.decBuf, r.readBuf = r.readBuf, r.decBuf
	}
	return r.eof, nil
}

// lenPrefixedReader is a [boundedReader] which is bounded by a quic-encoded length
// read during creation of the reader. This reader will only begin returing io.EOF
// when TryReadBoundary is called with no bytes remaining to be read.
//
// If you want a reader that just returns io.EOF after reading exactly x bytes, use
// [fixedLenReader] instead.
type lenPrefixedReader struct {
	r   io.Reader
	eof bool
	fr  *fixedLenReader
}

func newLenPrefixedReader(r io.Reader) *lenPrefixedReader {
	return &lenPrefixedReader{
		r:   r,
		eof: false,
		fr:  nil,
	}
}

func (r *lenPrefixedReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	if r.fr == nil {
		err := r.setupFixedLenReader()
		if err != nil {
			return 0, err
		}
	}

	if len(p) == 0 {
		return 0, nil
	}

	n, err := r.fr.Read(p)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (r *lenPrefixedReader) TryReadBoundary() (bool, error) {
	if r.eof {
		return false, nil
	}

	if r.fr == nil {
		err := r.setupFixedLenReader()
		if err != nil {
			return false, err
		}
	}

	r.eof = r.fr.Remaining() == 0
	return r.eof, nil
}

func (r *lenPrefixedReader) setupFixedLenReader() error {
	quicreader := quicvarint.NewReader(r.r)
	n, err := quicvarint.Read(quicreader)
	if err != nil {
		// if quicvarint returns EOF during reading the fixed length, that's an unexpected EOF
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	r.fr = newFixedLenReader(n, r.r)
	return nil
}

type delayedReader struct {
	setupFunc func() (io.Reader, error)
	setup     bool
	r         io.Reader
}

func newDelayedReader(setupFunc func() (io.Reader, error)) *delayedReader {
	return &delayedReader{
		setupFunc: setupFunc,
	}
}

func (dr *delayedReader) Read(p []byte) (int, error) {
	if !dr.setup {
		dr.setup = true
		r, err := dr.setupFunc()
		if err != nil {
			return 0, fmt.Errorf("failed to setup delayed reader: %w", err)
		}
		dr.r = r
	}

	return dr.r.Read(p)
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
