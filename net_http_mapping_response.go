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
	"strconv"
)

// MapFromHTTP1Response interprets the provided net/http response as a HTTP/1.1 response and maps
// it to a bhttp [Response].
//
// It will never set informational responses on the BHTTP response, as this information is not available in a net/http response.
//
// Note: DetermineResponseContentLength might consume the first byte of the reader on http.Response to check
// if the body actually contains data. If you don't want hr to be modified, be sure to pass in a clone.
func MapFromHTTP1Response(hr *http.Response) (*Response, error) {
	contentLen, knownLen, err := determineHTTPResponseContentLength(hr)
	if err != nil {
		return nil, fmt.Errorf("failed to map content length: %w", err)
	}

	statusCode, header, err := mapPreBodyFromHTTP1Response(hr)
	if err != nil {
		return nil, fmt.Errorf("failed to map pre-body: %w", err)
	}

	bdy := hr.Body
	if bdy == nil {
		bdy = http.NoBody
	}

	trailer := hr.Trailer
	// net/http automatically adds the Content-Length header for known length requests,
	// so we do the same here.
	if shouldSetContentLengthHeader(http.MethodPost, knownLen, contentLen) {
		header.Set("Content-Length", strconv.Itoa(int(contentLen)))
		header.Del("Trailer")
		trailer = http.Header{}
	}

	return &Response{
		KnownLength:     knownLen,
		ContentLength:   contentLen,
		FinalStatusCode: statusCode,
		FinalHeader:     header,
		Body:            bdy,
		Trailer:         trailer,
	}, nil
}

// MapToHTTP1Response maps a bhttp [Response] to a net/http Response
func MapToHTTP1Response(br *Response) (*http.Response, error) {
	hr, err := mapPreBodyToHTTP1Response(br.FinalStatusCode, br.FinalHeader)
	if err != nil {
		return nil, err
	}

	if hr.ContentLength == -1 && len(hr.Trailer) == 0 && (br.ContentLength == 0) {
		hr.ContentLength = 0
	}

	if len(hr.Trailer) == 0 {
		hr.Body = io.NopCloser(br.Body)
	} else { // we're late parsing the trailers out of r.Trailer and into the hr, here.
		hr.Body = io.NopCloser(io.MultiReader(
			br.Body,
			newDelayedReader(func() (io.Reader, error) { // IDK if I like this code being so far from where the action lives, with two delayed readers
				// once we make it here, the body of the bhttp request will have returned EOF
				// and its trailer should be set.
				for key := range br.Trailer {
					for _, val := range br.Trailer.Values(key) {
						hr.Trailer.Add(key, val)
					}
				}
				return eofReader{}, nil
			}),
		))
	}

	return hr, nil
}

// determineHTTPResponseContentLength determines the length of the response content in the same way that Go net/http does. The second
// return parameter indicates whether the response is known length (true) or indeterminate length (false).
//
// Note: determineHTTPResponseContentLength might consume the first byte of the reader on http.Response to check
// if the body actually contains data. If you don't want hr to be modified, be sure to pass in a clone.
func determineHTTPResponseContentLength(hr *http.Response) (int64, bool, error) {
	if chunked(hr.TransferEncoding) {
		return -1, false, nil
	}

	// Do the same check that http.Response.Write does.
	if hr.ContentLength == 0 && hr.Body != nil {
		// Is it actually 0 length? Or just unknown?
		var buf [1]byte
		n, err := hr.Body.Read(buf[:])
		if err != nil && err != io.EOF {
			return 0, false, err
		}
		if n == 0 {
			// Reset it to a known zero reader, in case underlying one
			// is unhappy being read repeatedly.
			hr.Body = http.NoBody
		} else {
			hr.ContentLength = -1
			hr.Body = struct {
				io.Reader
				io.Closer
			}{
				io.MultiReader(bytes.NewReader(buf[:1]), hr.Body),
				hr.Body,
			}
		}
	}

	return hr.ContentLength, hr.ContentLength >= 0, nil
}

// mapPreBodyFromHTTP1Response interprets the response as a HTTP/1.1 Response and returns
// the appropriate control data and headers for a bhttp response.
func mapPreBodyFromHTTP1Response(hr *http.Response) (int, http.Header, error) {
	err := validateFinalStatusCode(hr.StatusCode)
	if err != nil {
		return 0, nil, err
	}

	header := hr.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}

	// net/http sets these headers directly and doesn't take them from the user. We do the same here.
	header.Del("Content-Length")
	// Note: explicitly not mapped to BHTTP per section 6 of the BHTTP RFC.
	header.Del("Transfer-Encoding")
	header.Del("Trailer")

	// set trailer header if we have any pre-registered keys.
	if len(hr.Trailer) > 0 {
		val, err := trailerToHeaderVal(hr.Trailer)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to compose trailer header: %w", err)
		}

		header.Add("Trailer", val)
	}

	// set the content-length header for known-length responses.
	if hr.ContentLength >= 0 && !chunked(hr.TransferEncoding) {
		header.Add("Content-Length", strconv.Itoa(int(hr.ContentLength)))
	}

	return hr.StatusCode, header, nil
}

// mapPreBodyToHTTP1ServerSideRequest interprets the control data and headers as being for a HTTP/1.1 Go server side request
// and sets the appropriate values on the request.
//
// Roughly equivalent to [http.ReadResponse].
func mapPreBodyToHTTP1Response(statusCode int, h http.Header) (*http.Response, error) {
	err := validateFinalStatusCode(statusCode)
	if err != nil {
		return nil, errors.Join(err, InvalidMessageError{
			Err: fmt.Errorf("invalid status code"),
		})
	}

	hr := &http.Response{}

	hr.StatusCode = statusCode
	hr.Status = strconv.Itoa(statusCode)
	statusTxt := http.StatusText(statusCode)
	if statusTxt != "" {
		hr.Status += " " + statusTxt
	}
	hr.Proto = "HTTP/1.1"
	hr.ProtoMajor = 1
	hr.ProtoMinor = 1
	hr.Body = http.NoBody
	hr.Header = h.Clone()

	// handle the trailer
	if h.Get("Trailer") != "" {
		hr.Trailer, err = parseTrailerHeaderVal(h.Get("Trailer"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse trailer header value: %w", err)
		}
	}
	hr.Header.Del("Trailer")

	// move Content-Length header to ContentLength field if its present.
	if len(hr.Header.Values("Content-Length")) == 1 {
		contentLen, err := strconv.Atoi(hr.Header.Get("Content-Length"))
		if err != nil {
			return nil, InvalidMessageError{
				Err: fmt.Errorf("non-integer content-length header: %w", err),
			}
		}
		if contentLen < 0 {
			return nil, InvalidMessageError{
				Err: fmt.Errorf("content-length header must be positive, got %d", contentLen),
			}
		}
		hr.ContentLength = int64(contentLen)
	} else {
		hr.ContentLength = -1
	}
	// note: we keep the Content-Length header as unlike with requests, it isn't stripped
	// away on responses.

	return hr, nil
}

func validateFinalStatusCode(statusCode int) error {
	const (
		minCode = 200
		maxCode = 599
	)
	if statusCode < minCode || statusCode > maxCode {
		return fmt.Errorf(
			"status code must be a final status code between %d-%d, got: %d",
			minCode, maxCode, statusCode,
		)
	}
	return nil
}

// chunked indicates whether chunked is part of the encoding stack.
func chunked(te []string) bool {
	return len(te) > 0 && te[0] == "chunked"
}
