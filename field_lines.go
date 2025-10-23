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
	"net/http"
	"sort"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type fieldLine struct {
	name  []byte
	value []byte
}

func headerToFieldLines(h http.Header, isTrailer bool) ([]fieldLine, error) {
	var (
		lines []fieldLine
	)

	for key, vals := range h {
		line := fieldLine{
			// lower case header names like in HTTP/2,
			// also is what is being done in the RFC examples.
			name: []byte(strings.ToLower(key)),
		}

		if !httpguts.ValidHeaderFieldName(key) {
			return nil, errors.New("invalid header field name")
		}

		if isTrailer && !httpguts.ValidTrailerHeader(key) {
			return nil, errors.New("invalid trailer header")
		}

		if len(vals) == 0 {
			lines = append(lines, line)
			continue
		}

		for _, val := range vals {
			if !httpguts.ValidHeaderFieldValue(val) {
				return nil, errors.New("invalid header field value")
			}

			line.value = []byte(val)
			lines = append(lines, line)
		}
	}

	// sort these for stable tests
	sort.Slice(lines, func(i, j int) bool {
		return string(lines[i].name) < string(lines[j].name)
	})

	return lines, nil
}
