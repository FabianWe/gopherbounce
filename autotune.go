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

const (
	dummyPassword = "foobar-eggs-bacon-42"
	defaultPasses = 2
	defaultNumber = 10
)

func average(f func() error, passes, number int) (time.Duration, error) {
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

func averageSingle(f func() error, number int) (time.Duration, error) {
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
func TuneBcrypt(base *BcryptConf, duration time.Duration) (*BcryptConf, time.Duration, error) {
	if base != nil {
		base = base.Copy()
	}
	hasher := NewBcryptHasher(base)
	for cost := bcrypt.MinCost; cost <= bcrypt.MaxCost; cost++ {
		hasher.Cost = cost
		// run average
		f := func() error {
			_, err := hasher.Generate(dummyPassword)
			return err
		}
		avg, avgErr := average(f, defaultPasses, defaultNumber)
		if avgErr != nil {
			return nil, 0, avgErr
		}
		if avg >= duration {
			return &BcryptConf{Cost: cost}, avg, nil
		}
	}
	return nil, 0, fmt.Errorf("Can't reach duration %v", duration)
}

// TuneScrypt runs scrypt with increasing N values until an average runtime
// of at least duration is reached. Do not use this function to automatically
// compute your configuration, it is not safe enough! Run it, check the result
// and draw your own conclusions.
func TuneScrypt(base *ScryptConf, duration time.Duration) (*ScryptConf, time.Duration, error) {
	if base != nil {
		base = base.Copy()
	}
	hasher := NewScryptHasher(base)
	rounds := 15
	for Pow(2, int64(rounds)) > 0 {
		hasher.SetRounds(rounds)
		f := func() error {
			_, err := hasher.Generate(dummyPassword)
			return err
		}
		avg, avgErr := average(f, defaultPasses, defaultNumber)
		if avgErr != nil {
			return nil, 0, avgErr
		}
		if avg >= duration {
			conf := hasher.ScryptConf.Copy()
			// no need to do that but that's more clear
			conf.SetRounds(rounds)
			return conf, avg, nil
		}
		rounds++
	}
	return nil, 0, fmt.Errorf("Can't reach duration %v", duration)
}

// TuneArgon2i runs argon2i with increasing time values until an average runtime
// of at least duration is reached. Do not use this function to automatically
// compute your configuration, it is not safe enough! Run it, check the result
// and draw your own conclusions.
func TuneArgon2i(base *Argon2iConf, duration time.Duration) (*Argon2iConf, time.Duration, error) {
	if base != nil {
		base = base.Copy()
	}
	hasher := NewArgon2iHasher(base)
	var t uint32 = 3
	for t >= 3 {
		hasher.Time = t
		f := func() error {
			_, err := hasher.Generate(dummyPassword)
			return err
		}
		avg, avgErr := average(f, defaultPasses, defaultNumber)
		if avgErr != nil {
			return nil, 0, avgErr
		}
		if avg >= duration {
			conf := hasher.Argon2iConf.Copy()
			// no need to do that but that's more clear
			conf.Time = t
			return conf, avg, nil
		}
		t++
	}
	return nil, 0, fmt.Errorf("Can't reach duration %v", duration)
}

// TuneArgon2id runs argon2id with increasing time values until an average
// runtime of at least duration is reached. Do not use this function to
// automatically compute your configuration, it is not safe enough! Run it,
// check the result and draw your own conclusions.
func TuneArgon2id(base *Argon2idConf, duration time.Duration) (*Argon2idConf, time.Duration, error) {
	if base != nil {
		base = base.Copy()
	}
	hasher := NewArgon2idHasher(base)
	var t uint32 = 3
	for t >= 3 {
		hasher.Time = t
		f := func() error {
			_, err := hasher.Generate(dummyPassword)
			return err
		}
		avg, avgErr := average(f, defaultPasses, defaultNumber)
		if avgErr != nil {
			return nil, 0, avgErr
		}
		if avg >= duration {
			conf := hasher.Argon2idConf.Copy()
			// no need to do that but that's more clear
			conf.Time = t
			return conf, avg, nil
		}
		t++
	}
	return nil, 0, fmt.Errorf("Can't reach duration %v", duration)
}
