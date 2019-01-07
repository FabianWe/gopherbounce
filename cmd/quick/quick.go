// Copyright 2018, 2019 Fabian Wenzelmann
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

	"github.com/FabianWe/gopherbounce"
)

func main() {
	password := "foobar"
	hashed, hashErr := gopherbounce.Generate(gopherbounce.DefaultHasher, password)
	if hashErr != nil {
		panic(hashErr)
	}
	fmt.Println("Hashed password:", string(hashed))
	validator := gopherbounce.GuessValidatorFunc(hashed)
	okay := validator("foobar")
	if okay == nil {
		fmt.Println("Password correct")
	} else {
		fmt.Println("Password wrong")
	}
	okay = validator("eggs")
	if okay == nil {
		fmt.Println("Password correct")
	} else {
		fmt.Println("Password wrong")
	}
}
