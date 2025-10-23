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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http/httpguts"
)

// decodeField decodes a length prefix from r, validates its bounds and returns a reader that
// reads exactly the number of bytes for that field.
//
// The second return value indicates the number of bytes that were read to decode the length
// prefix. The length of the data can be retrieved by calling [Remaining] on the returned reader.
func decodeField(r io.Reader, minLen, maxLen uint64) (*fixedLenReader, error) { // nolint: unparam
	if minLen > maxLen {
		return nil, fmt.Errorf("minLen %d is greater than maxLen %d: %w", minLen, maxLen, ErrTooMuchData)
	}

	quicReader := quicvarint.NewReader(r)
	n, err := quicvarint.Read(quicReader)
	if err != nil {
		return nil, err
	}
	// n := quicn

	if n < minLen {
		return nil, InvalidMessageError{
			Err: fmt.Errorf("min length is %d, but got %d", minLen, n),
		}
	}
	if n > maxLen {
		return nil, fmt.Errorf("max length is %d, but got %d: %w", maxLen, n, ErrTooMuchData)
	}

	return newFixedLenReader(n, r), nil
}

// decodeFieldInclusive does the same as [decodeField] but takes the length bytes into account when validating maxLen.
func decodeFieldInclusive(r io.Reader, minLen, maxLen uint64) (*fixedLenReader, int, error) {
	if minLen > maxLen {
		return nil, 0, fmt.Errorf("min len %d is greater than max len %d: %w", minLen, maxLen, ErrTooMuchData)
	}

	quicReader := quicvarint.NewReader(r)
	quicn, err := quicvarint.Read(quicReader)
	if err != nil {
		return nil, 0, err
	}
	readN := quicvarint.Len(quicn)
	maxLen -= uint64(readN) // #nosec G115 -- Len is always going to be non-negative
	if quicn < minLen {
		return nil, readN, InvalidMessageError{
			Err: fmt.Errorf("min length is %d, but got %d", minLen, quicn),
		}
	}
	if quicn > maxLen {
		return nil, readN, fmt.Errorf("max data len is %d, but got %d: %w", maxLen, quicn, ErrTooMuchData)
	}

	return newFixedLenReader(quicn, r), readN, nil
}

func decodeFramingIndicator(r io.Reader) (framingIndicator, error) {
	quicReader := quicvarint.NewReader(r)
	n, err := quicvarint.Read(quicReader)
	if err != nil {
		return 0, fmt.Errorf("failed to read framing indicator: %w", err)
	}

	switch framingIndicator(n) {
	case knownLengthRequestFrame, knownLengthResponseFrame,
		indeterminateLengthRequestFrame, indeterminateLengthResponseFrame:
		return framingIndicator(n), nil
	default:
		return 0, InvalidMessageError{
			Err: fmt.Errorf("invalid framing indicator: %d", n),
		}
	}
}

func decodeResponseStatusCode(r io.Reader) (int, error) {
	quicReader := quicvarint.NewReader(r)
	code, err := quicvarint.Read(quicReader)
	if err != nil {
		return 0, fmt.Errorf("failed to read framing indicator: %w", err)
	}

	if code > 599 {
		return 0, InvalidMessageError{
			Err: fmt.Errorf("invalid status code: %d", code),
		}
	}

	return int(code), nil // #nosec G115 -- status code can never be non zero
}

func decodeRequestControlData(r io.Reader) (RequestControlData, error) {
	control := RequestControlData{}
	var err error
	fr, err := decodeField(r, 0, 64)
	if err != nil {
		return control, fmt.Errorf("failed to read method length: %w", err)
	}

	control.Method, _, err = fr.ReadRemaining()
	if err != nil {
		return control, fmt.Errorf("failed to read method: %w", err)
	}

	fr, err = decodeField(r, 0, 64)
	if err != nil {
		return control, fmt.Errorf("failed to read scheme length: %w", err)
	}

	control.Scheme, _, err = fr.ReadRemaining()
	if err != nil {
		return control, fmt.Errorf("failed to read scheme: %w", err)
	}

	fr, err = decodeField(r, 0, 256)
	if err != nil {
		return control, fmt.Errorf("failed to read authority length: %w", err)
	}

	control.Authority, _, err = fr.ReadRemaining()
	if err != nil {
		return control, fmt.Errorf("failed to read authority: %w", err)
	}

	fr, err = decodeField(r, 0, 4096)
	if err != nil {
		return control, fmt.Errorf("failed to read path length: %w", err)
	}

	control.Path, _, err = fr.ReadRemaining()
	if err != nil {
		return control, fmt.Errorf("failed to read path: %w", err)
	}

	return control, nil
}

// minFieldLineLen is the minimum length of valid field line.
const minEncodedFieldLineLen = 3

// fieldSectionDecoder decodes sections of field lines.
type fieldSectionDecoder struct {
	maxSectionLen uint64
	isTrailer     bool
}

func (d *fieldSectionDecoder) decode(buf *bytes.Buffer, r io.Reader, knownLen bool) (http.Header, error) {
	if d.maxSectionLen < minEncodedFieldLineLen && d.maxSectionLen != 0 {
		return nil, fmt.Errorf("max section length must be 0, or greater than or equal to %d, got %d", minEncodedFieldLineLen, d.maxSectionLen)
	}

	buf.Reset()

	// Set up the correct reader, depending on whether we're
	// decoding a known length or indeterminate length section.
	var br boundedReader
	if knownLen {
		br = newLenPrefixedReader(r)
	} else {
		br = newZeroTerminatedReader(r)
	}

	lines, err := d.fieldLinesToTextProto(buf, br)
	if err != nil {
		return nil, err
	}

	if lines == 0 {
		// don't bother parsing an empty header.
		return http.Header{}, nil
	}

	// Write a final newline to indicate end of text proto headers.
	_, err = buf.Write([]byte{'\n'})
	if err != nil {
		return nil, fmt.Errorf("failed to write final newline: %w", err)
	}

	// At this point the buffer contains the field lines encoded as a regular HTTP Header.
	// We now use the same package that net/http uses internally to parse these headers. This
	// way we don't need to re-implement the header parsing/combining logic ourselves.
	tpReader := textproto.NewReader(bufio.NewReader(buf))
	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil {
		return nil, InvalidMessageError{
			Err: errors.New("field lines form invalid MIME header"),
		}
	}

	// check if trailer field names are allowed.
	if d.isTrailer {
		for key := range mimeHeader {
			if !httpguts.ValidTrailerHeader(key) {
				return nil, InvalidMessageError{
					Err: fmt.Errorf("invalid trailer header name %s", key),
				}
			}
		}
	}

	return http.Header(mimeHeader), nil
}

func (d *fieldSectionDecoder) fieldLinesToTextProto(buf *bytes.Buffer, r boundedReader) (int, error) {
	lines := 0
	for {
		ok, err := r.TryReadBoundary()
		if err != nil {
			return lines, fmt.Errorf("failed to read boundary: %w", err)
		}
		if ok {
			break
		}

		remaining := d.maxSectionLen
		isPseudoheader, err := d.fieldLineToTextProto(buf, r, remaining)
		if err != nil {
			return lines, fmt.Errorf("field line %d: %w", lines, err)
		}

		if isPseudoheader {
			if lines > 0 {
				return lines, InvalidMessageError{
					Err: errors.New("pseudo header after regular headers"),
				}
			}
			continue
		}
		lines++
	}

	return lines, nil
}

// fieldLineToTextProto decodes a single field line from the reader and writes it as a text proto line to the buffer.
func (d *fieldSectionDecoder) fieldLineToTextProto(buf *bytes.Buffer, r boundedReader, remaining uint64) (bool, error) {
	// read the nameReader and write it to the buffer
	// note: names must be at least 1 byte long.
	nameReader, n, err := decodeFieldInclusive(r, 1, remaining)
	if err != nil {
		return false, fmt.Errorf("failed to read name length: %w", err)
	}

	nameStart := buf.Len()
	nameLen, err := buf.ReadFrom(nameReader)
	if err != nil {
		return false, fmt.Errorf("failed to write name to buffer: %w", err)
	}

	// check if this name is a pseudo-header.
	name := buf.Bytes()[nameStart : nameStart+int(nameLen)]
	isPseudoHeader := isPseudoHeader(name)
	if isPseudoHeader {
		if d.isTrailer {
			return false, InvalidMessageError{
				Err: errors.New("pseudo-header in trailer"),
			}
		}

		if isReservedPseudoHeader(name) {
			return false, InvalidMessageError{
				Err: errors.New("reserved pseudo-header"),
			}
		}
	}

	remaining -= uint64(n) + uint64(nameLen) // #nosec G115

	// Write a ':' to separate the name and value.
	_, err = buf.Write([]byte{':', ' '})
	if err != nil {
		return false, fmt.Errorf("failed to write separator to buffer: %w", err)
	}

	// read the valReader and write it to the buffer.
	valReader, _, err := decodeFieldInclusive(r, 0, remaining)
	if err != nil {
		return false, fmt.Errorf("failed to read value length: %w", err)
	}
	_, err = buf.ReadFrom(valReader)
	if err != nil {
		return false, fmt.Errorf("failed to write value to buffer: %w", err)
	}

	// Write a newline to separate header lines.
	_, err = buf.Write([]byte{'\n'})
	if err != nil {
		return false, fmt.Errorf("failed to write newline: %w", err)
	}

	if isPseudoHeader {
		// pseudo headers are not encoded to the textproto for now. Truncate buf to back before we wrote this text line.
		buf.Truncate(nameStart)
	}

	return isPseudoHeader, nil
}

func isPseudoHeader(s []byte) bool {
	// must begin with a colon
	if len(s) < 2 || s[0] != ':' {
		return false
	}

	// rest of the characters must be lowercase letters, numbers or hyphens.
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}

	return true
}

func isReservedPseudoHeader(s []byte) bool {
	// pseudo header names that are not allowed according to the Section 3.6 of the RFC:
	//
	// https://www.rfc-editor.org/rfc/rfc9292.html#name-header-and-trailer-field-li
	switch string(s) {
	case ":method", ":scheme", ":authority", ":path", ":status":
		return true
	default:
		return false
	}
}

type indeterminateLengthContent struct {
	r     boundedReader
	eof   bool
	chunk *fixedLenReader
}

func decodeIndeterminateLengthContent(r io.Reader) *indeterminateLengthContent {
	return &indeterminateLengthContent{
		r:     newZeroTerminatedReader(r),
		eof:   false,
		chunk: nil,
	}
}

func (r *indeterminateLengthContent) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}
	var chunkN int
	// read a chunk if we have one.
	if r.chunk != nil && r.chunk.Remaining() > 0 {
		n, err := r.chunk.Read(p)
		if err == nil || !errors.Is(err, io.EOF) {
			// no error, or a non-EOF error.
			return n, err
		}

		// io.EOF, continue on to the next read.
		chunkN = n
	}

	// past the chunk or no chunk, attempt to read the boundary.
	ended, err := r.r.TryReadBoundary()
	if err != nil {
		return chunkN, err
	}

	if ended {
		r.eof = true
		return chunkN, io.EOF
	}

	// no boundary, read a chunk.
	r.chunk, err = decodeField(r.r, 1, quicvarint.Max)
	if err != nil {
		return chunkN, fmt.Errorf("failed to decode len prefix of the chunk: %w", err)
	}

	// continue with the next read.
	return chunkN, nil
}

type padding struct {
	eof bool
	r   io.Reader
	buf *bytes.Buffer
}

func newPadding(r io.Reader, buf *bytes.Buffer) *padding {
	return &padding{
		eof: false,
		r:   r,
		buf: buf,
	}
}

func (p *padding) Read([]byte) (int, error) {
	if p.eof {
		return 0, io.EOF
	}

	p.buf.Reset()
	b := p.buf.AvailableBuffer()
	b = b[:cap(b)]
	n, err := p.r.Read(b)
	if n > 0 {
		// validate padding.
		for _, paddingByte := range b[:n] {
			if paddingByte != 0x00 {
				return 0, InvalidMessageError{
					Err: fmt.Errorf("invalid padding byte %d, should be %d", paddingByte, 0x00),
				}
			}
		}
	}
	if errors.Is(err, io.EOF) {
		p.eof = true
	}
	return 0, err
}
