// Copyright 2018 Fabian Wenzelmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This code is inspired by the following file on github:
// https://github.com/golang/crypto/blob/master/bcrypt/base64.go
// 470549d on Jan 25, 2012

// The corresponding license file from the package authors:
//
// Copyright (c) 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// TODO remove this padding stuff, just makes everything more complicated

package gopherbounce

import "encoding/base64"

type Base64Encoding struct {
	Alphabet      string
	Encoding      *base64.Encoding
	RemovePadding bool
}

func NewBase64Encoding(alphabet string, removePadding bool) *Base64Encoding {
	return &Base64Encoding{
		Alphabet:      alphabet,
		Encoding:      base64.NewEncoding(alphabet),
		RemovePadding: removePadding,
	}
}

func (enc *Base64Encoding) SetAlphabet(alphabet string) {
	enc.Alphabet = alphabet
	enc.Encoding = base64.NewEncoding(alphabet)
}

func (enc *Base64Encoding) Base64Encode(src []byte) []byte {
	n := enc.Encoding.EncodedLen(len(src))
	dst := make([]byte, n)
	enc.Encoding.Encode(dst, src)
	if enc.RemovePadding {
		for n > 0 && dst[n-1] == '=' {
			n--
		}
	}
	return dst[:n]
}

func (enc *Base64Encoding) Base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, enc.Encoding.DecodedLen(len(src)))
	n, err := enc.Encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

const Defaultalphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var DefaultEncoding = NewBase64Encoding(Defaultalphabet, false)

func Base64Encode(src []byte) []byte {
	return DefaultEncoding.Base64Encode(src)
}

func Base64Decode(src []byte) ([]byte, error) {
	return DefaultEncoding.Base64Decode(src)
}
