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

package gopherbounce

import (
  "fmt"
  "time"

  "golang.org/x/crypto/bcrypt"
)

var dummyPassword = "foobar-eggs-bacon-42"

func average(f func() error, passes, number int) (time.Duration , error) {
  currentMin, err := averageSingle(f, number)
  if err != nil {
    return 0, err
  }
  var next time.Duration
  for i := 1; i < passes; i++ {
    next, err = averageSingle(f, number)
    if err != nil {
      return 0, err
    }
    if next < currentMin {
      currentMin = next
    }
  }
  return currentMin, nil
}

func averageSingle(f func() error, number int) (time.Duration , error){
  sum := time.Duration(0)
  for i := 0; i < number; i++ {
    start := time.Now()
    err := f()
    execTime := time.Since(start)
    if err != nil {
      return 0, err
    }
    sum += execTime
  }
  return sum / time.Duration(number), nil
}

// TuneBcrypt runs bcrypt with increasing cost values until an average runtime
// of at least duration is reached. Do not use this function to automatically
// compute your configuration, it is not safe enough! Run it, check the result
// and draw your own conclusions.
func TuneBcrypt(duration time.Duration) (*BcryptConf, time.Duration, error) {
  hasher := NewBcryptHasher(nil)
  for cost := bcrypt.MinCost; cost <= bcrypt.MaxCost; cost++ {
    hasher.Cost = cost
    // run average
    f := func() error {
      _, err := hasher.Generate(dummyPassword)
      return err
    }
    avg, avgErr := average(f, 2, 10)
    if avgErr != nil {
      return nil, 0, avgErr
    }
    if avg >= duration {
      return &BcryptConf{Cost: cost}, avg, nil
    }
  }
  return nil, 0, fmt.Errorf("Can't reach duration %v", duration)
}
