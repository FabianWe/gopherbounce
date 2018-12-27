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

package main

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/FabianWe/gopherbounce"
)

func main() {
	x := readPassword()

	var hashers []gopherbounce.Hasher = []gopherbounce.Hasher{gopherbounce.Bcrypt, gopherbounce.Scrypt,
		gopherbounce.Argon2i, gopherbounce.Argon2id}

	hashes := make([][]byte, len(hashers))

	for i, hasher := range hashers {
		fmt.Println("Building hash with", reflect.TypeOf(hasher))
		start := time.Now()
		hash, err := hasher.Generate(x)
		execTime := time.Since(start)
		if err != nil {
			fmt.Println("There was an error:", err.Error())
		} else {
			fmt.Printf("Done after %v, computed the hash %s with length %d (why would you print that??)\n",
				execTime, hash, len(hash))
			hashes[i] = hash
		}
		fmt.Println(strings.Repeat("-", 20))
	}

	fmt.Printf("\n%s\n", strings.Repeat("#", 20))

	fmt.Println("Now verify your password with all hashers!")
	check := readPassword()
	for i := 0; i < len(hashers); i++ {
		hasher := hashers[i]
		fmt.Println("Next hasher is", reflect.TypeOf(hasher))
		hash := hashes[i]
		start := time.Now()
		compare := hasher.Compare(hash, check)
		execTime := time.Since(start)
		fmt.Println("Comparison took", execTime)
		if compare == nil {
			fmt.Println("Check, passwords match!")
		} else {
			switch v := compare.(type) {
			case gopherbounce.SyntaxError:
				fmt.Println("Hmm something is wrong with the syntax...", v.Error())
			case gopherbounce.VersionError, gopherbounce.AlgIDError:
				fmt.Println("Hmmm did you use the wrong hasher for this hash?...", v.Error())
			case gopherbounce.PasswordMismatchError:
				fmt.Println("The passwords do not match")
			default:
				fmt.Println("Something else went wrong...", v.Error())
			}
		}
		fmt.Println(strings.Repeat("-", 20))
	}

}

func readPassword() string {
	fmt.Print("Enter password: ")
	var input string
	fmt.Scanln(&input)
	return input
}
