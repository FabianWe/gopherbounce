// Copyright 2019 Fabian Wenzelmann
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

package tests

import (
	"testing"

	"github.com/FabianWe/gopherbounce"
)

var (
	phcStr1       = "$scrypt$ln=16,r=8,p=1$UmleFePI42glSzbKObHKIgVEE8JZLQXFTWC9Hb7IB97wRgiZvk3TdCJr0vCAj1OD1p42gbI8bDMTYvsQgUYSDg$Hn9Bm8nVoSH4/tTzS6gpKWuEaQMce7P3yN2eNrG4SUb7X3R+uQWEgOwSGMVKsqncz/8LSRfjg0VtQ2YA1mi7Sg"
	phcParseDummy *gopherbounce.PHC
)

func BenchmarkParsePHC(b *testing.B) {
	for n := 0; n < b.N; n++ {
		res, err := gopherbounce.ParsePHC(phcStr1, gopherbounce.PHCScryptConfig)
		if err != nil {
			panic(err)
		}
		phcParseDummy = res
	}
}

func BenchmarkParsePHCAlternate(b *testing.B) {
	for n := 0; n < b.N; n++ {
		res, err := gopherbounce.ParsePHCAlternate(phcStr1, gopherbounce.PHCScryptConfig)
		if err != nil {
			panic(err)
		}
		phcParseDummy = res
	}
}
