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
	"net/http"

	"github.com/quic-go/quic-go/quicvarint"
)

type intEncoder struct {
	buf     *bytes.Buffer
	n       uint64
	encoded bool
}

// newEncodedInt returns an int encoder as well as the max length of the encoding
func newEncodedInt(buf *bytes.Buffer, n uint64) (*intEncoder, int) {
	maxLen := 0
	if n <= quicvarint.Max {
		// this if really shouldn't be needed as all fields are explicitly
		// checked before encoders are created. Just checking to prevent a panic
		// from quicvarint.
		maxLen = quicvarint.Len(n)
	}

	return &intEncoder{
		buf:     buf,
		n:       n,
		encoded: false,
	}, maxLen
}

func (e *intEncoder) Read(p []byte) (int, error) {
	// again, this really shouldn't be happening here as all fields are explicitly
	// checked before encoders are created. Just checking here to prevent quicvarint
	// from panicing.
	if e.n < quicvarint.Min || e.n > quicvarint.Max {
		return 0, fmt.Errorf("%d can't be QUIC encoded (min %d, max %d)", e.n, quicvarint.Min, quicvarint.Max)
	}

	if !e.encoded {
		e.buf.Reset()
		nBytes := quicvarint.Append(nil, e.n)
		_, err := e.buf.Write(nBytes)
		if err != nil {
			return 0, fmt.Errorf("failed to quicencode: %w", err)
		}
		e.encoded = true
	}

	return e.buf.Read(p)
}

func newEncodedTerminator(buf *bytes.Buffer) io.Reader {
	// Content Terminator (i) = 0
	r, _ := newEncodedInt(buf, uint64(0))
	return r
}

func newEncodedFramingIndicator(buf *bytes.Buffer, fi framingIndicator) io.Reader {
	// Framing Indicator (i) = 0|1|2|3
	r, _ := newEncodedInt(buf, uint64(fi))
	return r
}

type encodedContentChunks struct {
	r io.Reader

	wasRead bool
	eof     bool

	buf         *bytes.Buffer
	maxLenBytes int
	buffer      []byte

	lenB      []byte
	remaining []byte
}

func newEncodedContentChunks(buf *bytes.Buffer, r io.Reader) *encodedContentChunks {
	return &encodedContentChunks{
		r:   r,
		buf: buf,
	}
}

func (r *encodedContentChunks) setup() error {
	// while we haven't returned io.EOF this reader owns the encoding bytes.Buffer. Usually, you
	// don't wan to work directly with the slice held by this buffer, but it should be okay here,
	// since we know that no-one else is using the buffer.
	r.buffer = r.buf.Bytes()[:r.buf.Cap()]
	bufLen := len(r.buffer)
	r.maxLenBytes = maxLenBytesForBufferOfLen(uint64(bufLen))

	if len(r.buffer) < 2 {
		return fmt.Errorf("buffer should be at least two bytes, got %d", len(r.buffer))
	}

	return nil
}

func (r *encodedContentChunks) Read(p []byte) (int, error) {
	if len(r.remaining) > 0 {
		n := copy(p, r.remaining)
		r.remaining = r.remaining[n:]
		return n, nil
	}

	if r.eof {
		return 0, io.EOF
	}

	if !r.wasRead {
		err := r.setup()
		if err != nil {
			return 0, err
		}
		r.wasRead = true
	}

	// read up to max buffer length into chunk.
	// resize remaining to be
	r.remaining = r.buffer[r.maxLenBytes:cap(r.buffer)]
	dataLen, err := r.r.Read(r.remaining)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return 0, err
		}
		r.eof = true
	}
	// chunks of 0 length are not allowed according to the RFC, we should return
	// and try to read more data on a later read.
	if dataLen == 0 {
		r.remaining = r.buffer[r.maxLenBytes:r.maxLenBytes] // no data was read.
		return 0, err
	}

	// check to prevent casting overflow
	if dataLen < 0 {
		return 0, errors.New("Read() returned negative length")
	}
	ulen := uint64(dataLen)

	// there is data to read.
	lenBytes := quicvarint.Len(ulen)
	padLeft := r.maxLenBytes - lenBytes
	r.lenB = r.buffer[padLeft:r.maxLenBytes]
	_ = quicvarint.Append(r.lenB[:0], ulen)

	// resize remaining to fit both length prefix and content.
	r.remaining = r.buffer[padLeft : r.maxLenBytes+dataLen]

	// copy from remaining to p
	n := copy(p, r.remaining)
	r.remaining = r.remaining[n:]
	return n, nil
}

func maxLenBytesForBufferOfLen(n uint64) int {
	if quicvarint.Len(n-1) == 1 {
		return 1
	}

	if quicvarint.Len(n-2) == 2 {
		return 2
	}

	if quicvarint.Len(n-4) == 4 {
		return 4
	}

	return 8
}

// newLenPrefixedData returns a reader that will read the length and then the message
func newLenPrefixedData(buf *bytes.Buffer, length uint64, data io.Reader) (io.Reader, uint64) {
	lenPart, lenLen := newEncodedInt(buf, length)
	totalLen := uint64(lenLen) + length // #nosec G115 -- the length of the quic int is int, but we are returning the whole length so we return a uint64
	return io.MultiReader(
		lenPart,
		newFixedLenReader(length, data),
	), totalLen
}

func newEncodedRequestControlData(buf *bytes.Buffer, ctrl RequestControlData) io.Reader {
	// Request Control Data {
	//   Method Length (i),
	//   Method (..),
	//   Scheme Length (i),
	//   Scheme (..),
	//   Authority Length (i),
	//   Authority (..),
	//   Path Length (i),
	//   Path (..),
	// }
	readers := make([]io.Reader, 4)
	for i, data := range [][]byte{ctrl.Method, ctrl.Scheme, ctrl.Authority, ctrl.Path} {
		part, _ := newLenPrefixedData(buf, uint64(len(data)), bytes.NewReader(data))
		readers[i] = part
	}
	return io.MultiReader(readers...)
}

func newEncodedResponseStatusCode(buf *bytes.Buffer, statusCode int) io.Reader {
	// Informational Response Control Data {
	//   Status Code (i) = 100..199,
	// }

	// Final Response Control Data {
	//   Status Code (i) = 200..599,
	// }

	// The status code is a QUIC encoded integer
	lenPart, _ := newEncodedInt(buf, uint64(statusCode)) // #nosec G115 -- status code is always a positive number
	return lenPart
}

func newEncodedFieldSection(buf *bytes.Buffer, knownLen bool, lines []fieldLine) io.Reader {
	fieldLinesReader, encLen := newEncodedFieldLines(buf, lines)
	if knownLen {
		// Known-Length Field Section {
		//   Length (i),
		//   Field Line (..) ...,
		// }
		lenReader, _ := newEncodedInt(buf, encLen)
		return io.MultiReader(lenReader, fieldLinesReader)
	}
	// Indeterminate-Length Field Section {
	//   Field Line (..) ...,
	//   Content Terminator (i) = 0,
	// }
	return io.MultiReader(fieldLinesReader, newEncodedTerminator(buf))
}

func newEncodedContent(buf *bytes.Buffer, knownLen bool, contentLen uint64, r io.Reader) io.Reader {
	if knownLen {
		// Known-Length Content {
		//   Content Length (i),
		//   Content (..),
		// }
		r, _ := newLenPrefixedData(buf, contentLen, r)
		return r
	}

	// Indeterminate-Length Content {
	//   Indeterminate-Length Content Chunk (..) ...,
	//   Content Terminator (i) = 0,
	// }
	//
	// Indeterminate-Length Content Chunk {
	//   Chunk Length (i) = 1..,
	//   Chunk (..),
	// }
	if r == nil {
		return newEncodedTerminator(buf)
	}

	return io.MultiReader(
		newEncodedContentChunks(buf, r),
		newEncodedTerminator(buf),
	)
}

func newEncodedFieldLines(buf *bytes.Buffer, lines []fieldLine) (io.Reader, uint64) {
	// Field Line (..) ...
	totalLen := uint64(0)
	readers := make([]io.Reader, len(lines)*2)
	for i, line := range lines {
		// Field Line {
		//   Name Length (i) = 1..,
		//   Name (..),
		//   Value Length (i),
		//   Value (..),
		// }
		namePart, nameLen := newLenPrefixedData(buf, uint64(len(line.name)), bytes.NewReader(line.name))
		valPart, valLen := newLenPrefixedData(buf, uint64(len(line.value)), bytes.NewReader(line.value))
		readers[i*2] = namePart
		readers[i*2+1] = valPart
		totalLen += nameLen + valLen
	}

	return io.MultiReader(readers...), totalLen
}

func newEncodedTrailerFieldLines(buf *bytes.Buffer, knownLength bool, trailer http.Header) io.Reader {
	if len(trailer) == 0 {
		return newEncodedFieldSection(buf, knownLength, nil)
	}

	return newDelayedReader(func() (io.Reader, error) {
		lines, err := headerToFieldLines(trailer, true)
		if err != nil {
			return nil, fmt.Errorf("failed to get header lines for trailer: %w", err)
		}

		return newEncodedFieldSection(buf, knownLength, lines), nil
	})
}
