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

// Request is the BHTTP representation of a net/http request that the encoders and decoders work with.
type Request struct {
	// KnownLength indicates whether the request should/is encoded as a known or indeterminate
	// length message.
	KnownLength bool
	// ContentLength is the Body length of a known length request. Ignored for indeterminate length messages.
	ContentLength int64
	// ControlData contains the RequestControlData. This data is passed as-is to the encoded/decoded messages,
	// mapping functions should take extra care to validate this data.
	ControlData RequestControlData
	// Header contains the headers that will be encoded to the BHTTP message.
	//
	// This might differ from what the original net/http request contains as net/http manages a few headers
	// behind the scenes.
	//
	// For example, while net/http takes the Content-Length header from the .ContentLength field on the original
	// request, the Content-Length header should be set in this map (if it's used).
	Header http.Header
	// Body usually reads the body of the original net/http request.
	Body io.Reader
	// Trailer works similar to the http.Request.Trailer field. It is up the MapFunc to:
	// - Initialize the keys of the Trailer map.
	// - Ensure that an appropriate Trailer header is added to the Header field.
	// - The values of the Trailer map are set when Body returns io.EOF.
	Trailer http.Header
}

// RequestControlData contains the control data for a request.
//
// RFC9292 (BHTTP):
// The values of these fields follow the rules in HTTP/2 (Section 8.3.1 of [HTTP/2]) that apply to
// the ":method", ":scheme", ":authority", and ":path" pseudo-header fields, respectively. However,
// where the ":authority" pseudo-header field might be omitted in HTTP/2, a zero-length value is
// encoded instead.
//
// Note: BHTTP RFC only specifies to encode a zero-length value when the authority
// field is omitted. However, in HTTP/2 :scheme and :path can also be omitted. We'll encode zero length
// values for these cases as well.
//
// RFC9113 8.1.2.3:
// https://www.rfc-editor.org/rfc/rfc9113#name-request-pseudo-header-field
type RequestControlData struct {
	// Method contains the :method pseudo-header according to RFC9113 Section 8.1.2.3.
	Method []byte
	// Scheme contains the :scheme pseudo-header according to RFC9113 Section 8.1.2.3.
	// Note: BHTTP RFC makes this required, so we can't omit it like in HTTP 2.
	Scheme []byte
	// Authority contains the :authority pseudo-header according to RFC9113 Section 8.1.2.3.
	// Note: BHTTP RFC requires us to provide an empty encoding when omitted.
	Authority []byte
	// Path contains the :scheme pseudo-header according to RFC9113 Section 8.1.2.3.
	// Note: BHTTP RFC makes this required, so we can't omit it like in HTTP 2.
	Path []byte
}

// RequestFromHTTP maps a net/http request to a [Request].
type RequestFromHTTP func(r *http.Request) (*Request, error)

// DefaultRequestFromHTTP is the default request mapping function used by the request encoder. It interprets net/http requests as
// unproxied HTTP/1.1 client side requests.
func DefaultRequestFromHTTP(hr *http.Request) (*Request, error) {
	return RequestFromHTTP1(hr, false, false)
}

// RequestEncoder encodes net/http requests to bhttp messages.
//
// An empty encoder is safe to use and is the recommended way to construct a new request encoder. An empty request
// encoder will:
//   - Interpret the net/http requests as unproxied HTTP/1.1 client side requests.
//   - Encode an indeterminate-length message where net/http would use chunked transfer encoding. BHTTP Message
//     chunks will at most be 4096 bytes in length.
//   - Not including padding in the message.
//
// If you need different encoding logic, use [NewKnownLengthRequestEncoder], [NewIndeterminateLengthRequestEncoder] or create
// a custom RequestEncoder by setting the fields below.
type RequestEncoder struct {
	// MapFunc maps a net/http Request to a BHTTP response. If this field is nil, [DefaultRequestFromHTTP] will be used
	// which interprets net/http requests as unproxied HTTP/1.1 client side requests.
	MapFunc RequestFromHTTP

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

// NewKnownLengthRequestEncoder returns an encoder that will encode all requests as known-length BHTTP messages, regardless
// of what the the net/http request looks like. Even requests that would normally use Transfer-Encoding: chunked will be
// encoded as known-length BHTTP messages.
//
// Note: this encoder might read the full body of the request into memory to determine its exact length.
func NewKnownLengthRequestEncoder() *RequestEncoder {
	return &RequestEncoder{
		MapFunc: func(hr *http.Request) (*Request, error) {
			br, err := DefaultRequestFromHTTP(hr)
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

// NewIndeterminateLengthRequestEncoder returns an encoder that will encode all requests as indeterminate-length BHTTP messages,
// regardless of what the net/http request looks like.
//
// Even requests where the Content-Length is known will be encoded as an indeterminate-length BHTTP message.
func NewIndeterminateLengthRequestEncoder() *RequestEncoder {
	return &RequestEncoder{
		MapFunc: func(hr *http.Request) (*Request, error) {
			br, err := DefaultRequestFromHTTP(hr)
			if err != nil {
				return nil, err
			}
			br.ContentLength = -1
			br.KnownLength = false
			return br, nil
		},
	}
}

// EncodeRequests encodes the provided net/http request as an bhttp message. The exact interpretation
// of the request depends on the MapFunc of this [RequestEncoder], see that type for more details.
//
// If this request has a body, the encoder will encode the body until EOF is encountered. It is the
// responsibility of the caller to close the body.
func (e *RequestEncoder) EncodeRequest(hr *http.Request) (*Message, error) {
	var (
		r   *Request
		err error
	)
	if e.MapFunc != nil {
		r, err = e.MapFunc(hr)
	} else {
		r, err = DefaultRequestFromHTTP(hr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to map net/http request to bhttp request: %w", err)
	}

	framingIndicator := knownLengthRequestFrame
	if !r.KnownLength {
		framingIndicator = indeterminateLengthRequestFrame
	}

	// create the header field lines.
	headerLines, err := headerToFieldLines(r.Header, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create header field lines: %w", err)
	}

	if e.orderFieldLinesFunc != nil {
		e.orderFieldLinesFunc(headerLines)
	}

	// Encoded message will be one of the following two formats:
	//
	// Known-Length Request {
	//   Framing Indicator (i) = 0,
	//   Request Control Data (..),
	//   Known-Length Field Section (..),
	//   Known-Length Content (..),
	//   Known-Length Field Section (..),
	//   Padding (..),
	// }
	//
	// Indeterminate-Length Request  {
	//   Framing Indicator (i) = 2,
	//   Request Control Data (..),
	//   Indeterminate-Length Field Section (..),
	//   Indeterminate-Length Content (..),
	//   Indeterminate-Length Field Section (..),
	//   Padding (..),
	// }

	// for known-length requests we will only need a buffer that can
	// contain a maximum length quicencoded integer (8 bytes).
	bufferLen := 8
	if !r.KnownLength {
		// for indeterminate length requests, we likely need to overwrite
		// the bufferLen to fit the content chunks.
		maxChunkLen := 4096
		if e.MaxEncodedChunkLen > 0 {
			maxChunkLen = e.MaxEncodedChunkLen
		}
		if maxChunkLen > bufferLen {
			bufferLen = maxChunkLen
		}
	}
	buf := bytes.NewBuffer(make([]byte, 0, bufferLen))

	uContentLength := uint64(max(0, r.ContentLength)) // #nosec G115 -- i thought the linter would be clever enough for this

	// set up the readers that together will form the encoded request.
	// each encoded part owns buf until it returns io.EOF from its Read.
	return &Message{
		framing:         framingIndicator,
		padToMultipleOf: e.PadToMultipleOf,
		encoded: io.MultiReader(
			newEncodedFramingIndicator(buf, framingIndicator),
			newEncodedRequestControlData(buf, r.ControlData),
			newEncodedFieldSection(buf, r.KnownLength, headerLines),
			newEncodedContent(buf, r.KnownLength, uContentLength, r.Body),
			newEncodedTrailerFieldLines(buf, r.KnownLength, r.Trailer),
		),
	}, nil
}

// RequestToHTTP maps a [Request] to a net/http request.
type RequestToHTTP func(ctx context.Context, r *Request) (*http.Request, error)

// DefaultRequestToHTTP is the default request mapping function used by the request decoder. It interprets BHTTP
// requests as unproxied HTTP/1.1 server side requests.
func DefaultRequestToHTTP(ctx context.Context, br *Request) (*http.Request, error) {
	return RequestToHTTP1(ctx, br, false, true)
}

const (
	defaultMaxHeaderBytes = 16 << 10 // 16KB
)

// RequestDecoder decodes a BHTTP message to a net/http request.
//
// An empty decoder is safe to use and is the recommended way to construct a new request decoder. An empty request decoder
// will:
// - Interpret the incoming BHTTP messages as unproxied HTTP/1.1 server side requests.
// - Allow for header sections of up to 16KB.
type RequestDecoder struct {
	// MaxHeaderBytes is the maximum number of header bytes that can be read. Will default to 16KB.
	MaxHeaderBytes int64

	// MapFunc determines how a BHTTP request is interpreted. If this field is nil, the decoder will default
	// to interpreting the BHTTP request as a an unproxied HTTP/1.1 server side request.
	MapFunc RequestToHTTP
}

// DecodeRequest decodes a request from the provided reader. The context of the request will be set to ctx.
func (d *RequestDecoder) DecodeRequest(ctx context.Context, r io.Reader) (*http.Request, error) {
	framing, err := decodeFramingIndicator(r)
	if err != nil {
		return nil, err
	}

	if !framing.request() {
		return nil, InvalidMessageError{
			Err: errors.New("expected a request, got a response"),
		}
	}

	control, err := decodeRequestControlData(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode control data: %w", err)
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
	header, err := headerDecoder.decode(buf, r, framing.knownLength())
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	// set up the bhttp request.
	br := &Request{
		KnownLength:   framing.knownLength(),
		ContentLength: -1, // will be updated for knownLength requests later
		ControlData:   control,
		Header:        header,
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
		// decode the body.
		bdy, err := decodeField(r, 0, quicvarint.Max)
		if err != nil {
			return nil, fmt.Errorf("failed to read body length: %w", err)
		}
		remaining := bdy.Remaining()
		if remaining > math.MaxInt {
			return nil, errors.New("reading a longer body than fits in a request")
		}
		br.ContentLength = int64(remaining)
		if br.ContentLength == 0 {
			bodyReader = http.NoBody
		} else {
			bodyReader = io.NopCloser(bdy)
		}
	} else {
		bodyReader = decodeIndeterminateLengthContent(r)
	}

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

	// Map the bhttp Request to a net/http request.
	var hr *http.Request
	if d.MapFunc != nil {
		hr, err = d.MapFunc(ctx, br)
	} else {
		hr, err = DefaultRequestToHTTP(ctx, br)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to map bhttp request to net/http request: %w", err)
	}

	return hr, nil
}

func (d *RequestDecoder) maxHeaderBytes() uint64 {
	if d.MaxHeaderBytes > 0 {
		return uint64(d.MaxHeaderBytes)
	}
	return defaultMaxHeaderBytes
}
