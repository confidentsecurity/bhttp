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
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"

	"github.com/quic-go/quic-go/quicvarint"
)

// Response is the bhttp representation of a net/http response that the encoders/decoders
// work with.
//
// A BHTTP encoded response represents a "resolved response", so it actually
// represents 0 or more informational 1xx responses followed by a final 2xx-5xx response.
type Response struct {
	// KnownLength indicates whether the response should/is encoded as a known or indeterminate
	// length message.
	KnownLength bool
	// ContentLength is the Body length of a known length request. Ignored for indeterminate length messages.
	ContentLength int64
	// Informational contains an array of InformationalResponses (1xx status codes and attendant headers)
	// They do not map to go Response objects, so would need to be manually encoded.
	Informational []InformationalResponse
	// FinalStatusCode contains the 2xx-5xx status code of the final response.
	FinalStatusCode int
	// FinalHeader contains the headers for the final response.
	//
	// This might differ from what the original net/http response contains as net/http manages a few headers
	// behind the scenes.
	//
	// For example, while net/http takes the Content-Length header from the .ContentLength field on the original response, the
	// Content-Length header should be set in this map (if it's used).
	FinalHeader http.Header
	// Body usually reads the body of the original net/http response.
	Body io.Reader
	// Trailer works similar to the http.Response.Trailer field. It is up the MapFunc to:
	// - Initialize the keys of the Trailer map.
	// - Ensure that an appropriate Trailer header is added to the Header field.
	// - The values of the Trailer map are set when Body returns io.EOF.
	Trailer http.Header
}

// InformationalResponse contains control data and header of an informational response response.
type InformationalResponse struct {
	StatusCode int
	// Header contains the headers as FieldLines for the BHTTP encoded message. This
	// usually differs from what a net/http response contains, as Go 	moves some headers
	// to/from fields. For example, the Host and Content-Length headers.
	Header http.Header
}

// ResponseFromHTTP maps a net/http response to a [Response].
type ResponseFromHTTP func(r *http.Response) (*Response, error)

// DefaultResponseFromHTTP interpret the net/http response as an unproxied HTTP/1.1 client side responses.
func DefaultResponseFromHTTP(hr *http.Response) (*Response, error) {
	return MapFromHTTP1Response(hr)
}

// ResponseEncoder encodes net/http responses to bhttp messages.
//
// An empty encoder is safe to use and is the recommended way to construct a new response encoder. An empty request
// response will:
//   - Interpret the net/http responses as unproxied HTTP/1.1 client side responses.
//   - Encode an indeterminate-length message where net/http would use chunked transfer encoding. BHTTP Message
//     chunks will at most be 4096 bytes in length.
//   - Not including padding in the message.
//
// If you need different encoding logic, use [NewKnownLengthResponseEncoder], [NewIndeterminateLengthResponseEncoder] or create
// a custom ResponseEncoder by setting the fields below.
type ResponseEncoder struct {
	// MapFunc maps a net/http response . If this field is nil, DefaultResponseMapFunc will be used.
	MapFunc ResponseFromHTTP

	// PadToMultipleOf pads the message with zeroes until it reaches a multiple of this number. 0 will add no padding.
	PadToMultipleOf uint64

	// MaxEncodedChunkLen is the maximum length of indeterminate length content chunks (including their length prefix). MaxEncodedChunkLen
	// should be at least 2 bytes so that it will always fit a quicencoded integer with some data. If this field is 0, it
	// will default to 4096.
	MaxEncodedChunkLen int

	// orderFieldLinesFunc is only used in tests to ensure field lines match the order of expected test output. Since net/http deals with headers
	// as maps we can't guarantee their order which makes testing against RFC examples a pain.
	orderFieldLinesFunc func(fl []fieldLine)
}

// NewKnownLengthResponseEncoder returns an encoder that will encode all responses as known-length BHTTP messages, regardless
// of what the the net/http response looks like. Even responses that would normally use Transfer-Encoding: chunked will be
// encoded as known-length BHTTP messages.
//
// Note: this encoder might read the full body of the response into memory to determine its exact length.
func NewKnownLengthResponseEncoder() *ResponseEncoder {
	return &ResponseEncoder{
		MapFunc: func(hr *http.Response) (*Response, error) {
			br, err := DefaultResponseFromHTTP(hr)
			if err != nil {
				return nil, err
			}

			if !br.KnownLength {
				buf := &bytes.Buffer{}
				contentLen, err := io.Copy(buf, br.Body)
				if err != nil {
					return nil, fmt.Errorf("failed to read body: %w", err)
				}
				br.Body = buf
				br.KnownLength = true
				br.ContentLength = contentLen
			}

			return br, nil
		},
	}
}

// NewIndeterminateLengthResponseEncoder returns an encoder that will encode all requests as indeterminate-length BHTTP messages,
// regardless of what the net/http request looks like.
//
// Even requests where the Content-Length is known will be encoded as an indeterminate-length BHTTP message.
func NewIndeterminateLengthResponseEncoder() *ResponseEncoder {
	return &ResponseEncoder{
		MapFunc: func(hr *http.Response) (*Response, error) {
			br, err := DefaultResponseFromHTTP(hr)
			if err != nil {
				return nil, err
			}
			br.ContentLength = -1
			br.KnownLength = false
			return br, nil
		},
	}
}

// EncodeResponse encodes the provided net/http response as an bhttp message. The exact interpretation
// of the request depends on the MapFunc of this [ResponseEncoding], see that type for more details.
//
// If this response has a body, the encoder will encode the body until EOF is encountered. It is the
// responsibility of the caller to close the body.
func (e *ResponseEncoder) EncodeResponse(hr *http.Response) (*Message, error) {
	var (
		r   *Response
		err error
	)
	if e.MapFunc != nil {
		r, err = e.MapFunc(hr)
	} else {
		r, err = MapFromHTTP1Response(hr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to map net/http response to bhttp response: %w", err)
	}

	framingIndicator := knownLengthResponseFrame
	if !r.KnownLength {
		framingIndicator = indeterminateLengthResponseFrame
	}

	// collect all field lines (informational and final)
	infHeaderLines := make([][]fieldLine, 0, len(r.Informational))
	for i, inf := range r.Informational {
		fl, err := headerToFieldLines(inf.Header, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create field lines for informational response %d: %w", i, err)
		}
		infHeaderLines = append(infHeaderLines, fl)
	}

	finalHeaderLines, err := headerToFieldLines(r.FinalHeader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create header field lines for final response: %w", err)
	}
	if e.orderFieldLinesFunc != nil {
		e.orderFieldLinesFunc(finalHeaderLines)
	}

	// Encoded message will be one of the following two formats:
	//
	// Known-Length Response {
	//   Framing Indicator (i) = 1,
	//   Known-Length Informational Response (..) ...,
	//   Final Response Control Data (..),
	//   Known-Length Field Section (..),
	//   Known-Length Content (..),
	//   Known-Length Field Section (..),
	//   Padding (..),
	// }
	//
	// Indeterminate-Length Response  {
	//   Framing Indicator (i) = 3,
	//   Indeterminate-Length Informational Response (..) ...,
	//   Final Response Control Data (..),
	//   Indeterminate-Length Field Section (..),
	//   Indeterminate-Length Content (..),
	//   Indeterminate-Length Field Section (..),
	//   Padding (..),
	// }

	// for known-length responses we will only need a buffer that can
	// contain a maximum length quicencoded integer (8 bytes).
	bufferLen := 8
	if !r.KnownLength {
		// for indeterminate length responses, we likely need to overwrite
		// the bufferLen to fit the content chunks.
		maxChunkLen := 4096
		if e.MaxEncodedChunkLen > 0 {
			maxChunkLen = e.MaxEncodedChunkLen
		}
		if maxChunkLen > bufferLen {
			bufferLen = maxChunkLen
		}
	}
	buf := bytes.NewBuffer(make([]byte, bufferLen))

	uContentLength := uint64(max(0, r.ContentLength)) // #nosec G115 -- i thought the linter would be clever enough for this

	// collect the encoded informational response readers
	infEncoded := make([]io.Reader, 0, len(r.Informational)*2)
	for i, resp := range r.Informational {
		infEncoded = append(
			infEncoded,
			newEncodedResponseStatusCode(buf, resp.StatusCode),
			newEncodedFieldSection(buf, r.KnownLength, infHeaderLines[i]),
		)
	}

	// set up the readers that together will form the encoded response.
	// each encoded part owns buf until it returns io.EOF from its Read.
	return &Message{
		framing:         framingIndicator,
		padToMultipleOf: e.PadToMultipleOf,
		encoded: io.MultiReader(
			newEncodedFramingIndicator(buf, framingIndicator),
			io.MultiReader(infEncoded...),
			newEncodedResponseStatusCode(buf, r.FinalStatusCode),
			newEncodedFieldSection(buf, r.KnownLength, finalHeaderLines),
			newEncodedContent(buf, r.KnownLength, uContentLength, r.Body),
			newEncodedTrailerFieldLines(buf, r.KnownLength, r.Trailer),
		),
	}, nil
}

// ResponseToHTTP maps a [Response] to a net/http response.
type ResponseToHTTP func(ctx context.Context, r *Response) (*http.Response, error)

type ResponseDecoder struct {
	// MaxHeaderBytes is the maximum number of header bytes that can be read. Will default to 16KB.
	MaxHeaderBytes int64

	// MapFunc maps a [*Response] to a net/http Response. If this field is nil, [*Response] will be mapped to a
	// server-side, unproxied response.
	MapFunc ResponseToHTTP
}

// DecodeResponse decodes a response from the provided reader. The context of the response will be set to ctx.
func (d *ResponseDecoder) DecodeResponse(ctx context.Context, r io.Reader) (*http.Response, error) {
	// Encoded message will be one of the following two formats:
	//
	// Known-Length Response {
	//   Framing Indicator (i) = 1,
	//   Known-Length Informational Response (..) ...,
	//   Final Response Control Data (..),
	//   Known-Length Field Section (..),
	//   Known-Length Content (..),
	//   Known-Length Field Section (..),
	//   Padding (..),
	// }
	//
	// Indeterminate-Length Response  {
	//   Framing Indicator (i) = 3,
	//   Indeterminate-Length Informational Response (..) ...,
	//   Final Response Control Data (..),
	//   Indeterminate-Length Field Section (..),
	//   Indeterminate-Length Content (..),
	//   Indeterminate-Length Field Section (..),
	//   Padding (..),
	// }

	framing, err := decodeFramingIndicator(r)
	if err != nil {
		return nil, err
	}
	if !framing.response() {
		return nil, InvalidMessageError{
			Err: errors.New("expected a response, got a request message"),
		}
	}

	// field section decoders.
	headerDecoder := fieldSectionDecoder{
		maxSectionLen: d.maxHeaderBytes(),
		isTrailer:     false,
	}
	trailerDecoder := fieldSectionDecoder{
		maxSectionLen: d.maxHeaderBytes(),
		isTrailer:     true,
	}

	buf := bytes.NewBuffer(make([]byte, 512))

	// set up the bhttp response.
	br := &Response{
		KnownLength:   framing.knownLength(),
		ContentLength: -1,            // will be updated for knownLength responses later
		Trailer:       http.Header{}, // TODO: Handle trailers.
	}

	// code the responses until we reach the final response status code.
	for {
		statusCode, err := decodeResponseStatusCode(r)
		if err != nil {
			return nil, fmt.Errorf("failed to decode status code: %w", err)
		}

		header, err := headerDecoder.decode(buf, r, framing.knownLength())
		if err != nil {
			return nil, fmt.Errorf("failed to decode header: %w", err)
		}

		// final response.
		if statusCode >= 200 {
			br.FinalStatusCode = statusCode
			br.FinalHeader = header
			break
		}

		// informational response.
		br.Informational = append(br.Informational, InformationalResponse{
			StatusCode: statusCode,
			Header:     header,
		})
	}

	// BHTTP allows for the body and trailer to be truncated under certain conditions. Truncated trailers
	// and bodies should be interpreted as being equivalent to being encoded as just the content terminator
	// (zero).
	//
	// BHTTP also allows for a message to be padded with an arbitrary amount of zeroes.
	//
	// These two properties enable us to deal with truncated body/trailers without dedicated handling by appending
	// two zeroes to each message.
	// - If the body and/or trailer are not the truncated, these two zeroes will be interpreted as padding.
	// - If the body and/or trailer are truncated these two zeroes will be interpreted as content-terminators.
	r = io.MultiReader(r, bytes.NewReader([]byte{0x00, 0x00}))

	var bodyReader io.Reader
	if framing.knownLength() {
		bdy, err := decodeField(r, 0, quicvarint.Max)
		if err != nil {
			return nil, fmt.Errorf("failed to read body length: %w", err)
		}
		remaining := bdy.Remaining()
		if remaining > math.MaxInt {
			return nil, errors.New("reading a longer body than fits in a response")
		}
		br.ContentLength = int64(remaining)
		if br.ContentLength == 0 {
			bodyReader = http.NoBody
		} else {
			bodyReader = bdy
		}
	} else {
		bodyReader = decodeIndeterminateLengthContent(r)
	}

	// Add the trailer decoder before converting to net/http
	br.Body = io.NopCloser(io.MultiReader(
		bodyReader,
		newDelayedReader(func() (io.Reader, error) {
			trailer, err := trailerDecoder.decode(buf, r, framing.knownLength())
			if err != nil {
				return nil, fmt.Errorf("failed to decode trailer: %w", err)
			}
			br.Trailer = trailer
			return newPadding(r, buf), nil
		}),
	))

	// Map the bhttp Response to a net/http response.
	var hr *http.Response
	if d.MapFunc != nil {
		hr, err = d.MapFunc(ctx, br)
	} else {
		hr, err = MapToHTTP1Response(br)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to map bhttp response to net/http response: %w", err)
	}

	return hr, nil
}

func (d *ResponseDecoder) maxHeaderBytes() uint64 {
	if d.MaxHeaderBytes > 0 {
		return uint64(d.MaxHeaderBytes)
	}
	return defaultMaxHeaderBytes
}
