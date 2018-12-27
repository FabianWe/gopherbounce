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
  "os"
  "strings"
  "time"

  "github.com/FabianWe/gopherbounce"
)

func main() {

  if len(os.Args) != 3 {
    fmt.Println("Invalid syntax")
    fmt.Printf("Usage: %s alg t\n", os.Args[0])
    fmt.Printf("Example: %s bcrypt 241ms\n", os.Args[0])
    os.Exit(1)
  }

  duration, parseErr := time.ParseDuration(os.Args[2])
  if parseErr != nil {
    fmt.Println("Invalid duration argument:", parseErr.Error())
    os.Exit(1)
  }

  switch strings.ToLower(os.Args[1]) {
  case "bcrypt":
    tuneBcrypt(duration)
  case "scrypt":
    tuneScrypt(duration)
  default:
    fmt.Printf("Invalid algorithm \"%s\"\n", os.Args[1])
    fmt.Println("Valid algorithms are")
    fmt.Println("  * bcrypt")
    os.Exit(1)
  }
}

func tuneBcrypt(duration time.Duration) {
  conf, avg, tuneErr := gopherbounce.TuneBcrypt(duration)
  if tuneErr != nil {
    fmt.Println("Error tuning bcrypt:", tuneErr.Error())
    os.Exit(1)
  }
  fmt.Println("bcrypt tuning computed the following config:", conf)
  fmt.Println("Average with this cost is", avg)
}

func tuneScrypt(duration time.Duration) {
  conf, avg, tuneErr := gopherbounce.TuneScrypt(duration)
  if tuneErr != nil {
    fmt.Println("Error tuning scrypt:", tuneErr.Error())
    os.Exit(1)
  }
  fmt.Println("scrypt tuning computed the following config:", conf)
  fmt.Println("Average with this cost is", avg)
}
