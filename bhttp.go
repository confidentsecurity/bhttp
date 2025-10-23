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
	"errors"
	"io"
)

// DefaultEncodingBufferLen is the default buffer length
const DefaultEncodingBufferLen = 4096

type Message struct {
	framing         framingIndicator
	encoded         io.Reader
	eof             bool
	padToMultipleOf uint64
	totalRead       uint64
}

func (m *Message) IsRequest() bool {
	return m.framing.request()
}
func (m *Message) IsResponse() bool {
	return m.framing.response()
}

func (m *Message) IsKnownLength() bool {
	return m.framing.knownLength()
}

func (m *Message) IsIndeterminateLength() bool {
	return m.framing.indeterminateLength()
}

func (m *Message) Read(p []byte) (int, error) {
	if m.eof {
		if m.padToMultipleOf == 0 {
			return 0, io.EOF
		}
		return m.pad(p)
	}

	n, err := m.encoded.Read(p)
	if n < 0 {
		return n, errors.New("Read returned negative value, out of spec")
	}
	m.totalRead += uint64(n)
	if err != nil && errors.Is(err, io.EOF) {
		m.eof = true
		if m.padToMultipleOf != 0 {
			if m.padRemaining() > 0 {
				err = nil
			}
			return n, err
		}
	}
	return n, err
}

func (m *Message) pad(p []byte) (int, error) {
	remaining := m.padRemaining()
	if remaining == 0 {
		return 0, io.EOF
	}
	padLen := min(remaining, len(p))
	for i := range padLen {
		p[i] = 0
		m.totalRead++
	}
	if remaining == padLen {
		return padLen, io.EOF
	}
	return padLen, nil
}

func (m *Message) padRemaining() int {
	mod := m.totalRead % m.padToMultipleOf
	if mod == 0 {
		return 0
	}

	wantedChunks := uint64(m.totalRead/m.padToMultipleOf) + 1
	return int(wantedChunks*m.padToMultipleOf - m.totalRead)
}

type framingIndicator byte

const (
	knownLengthRequestFrame          = framingIndicator(0)
	knownLengthResponseFrame         = framingIndicator(1)
	indeterminateLengthRequestFrame  = framingIndicator(2)
	indeterminateLengthResponseFrame = framingIndicator(3)
)

func (i framingIndicator) knownLength() bool {
	return i == knownLengthRequestFrame || i == knownLengthResponseFrame
}

func (i framingIndicator) indeterminateLength() bool {
	return i == indeterminateLengthRequestFrame || i == indeterminateLengthResponseFrame
}

func (i framingIndicator) request() bool {
	return i == knownLengthRequestFrame || i == indeterminateLengthRequestFrame
}

func (i framingIndicator) response() bool {
	return i == knownLengthResponseFrame || i == indeterminateLengthResponseFrame
}
