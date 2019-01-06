# gopherbounce
gopherbounce is a Golang authentication framework. It bundles [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt), [scrypt](https://godoc.org/golang.org/x/crypto/scrypt) and [argon2](https://godoc.org/golang.org/x/crypto/argon2) (argon2i and argon2id) under a common interface. It provides easy to use functions for hashing and validating passwords.
Find the full code documentation on [GoDoc](https://godoc.org/github.com/FabianWe/gopherbounce).

# DO NOT USE THIS LIBRARY YET, IT IS STILL UNDER DEVELOPMENT

## Installation
The easiest way: `go get -u github.com/FabianWe/gopherbounce`.

## Quickstart
The following example demonstrates how to use this library in the most easy way. It first creates the password hash of the clear text password and then compares it with another clear text password. Just create the string variables `password` and `testPassword`. A runnable example can be found in [quick.go](https://github.com/FabianWe/gopherbounce/blob/master/cmd/quick/quick.go)

```go
hashed, hashErr := gopherbounce.DefaultHasher.Generate(password)
if hashErr != nil {
  panic(hashErr)
}
fmt.Println("Hashed password:", string(hashed))
validator := gopherbounce.GuessValidatorFunc(hashed)
okay := validator(testPassword)
if okay == nil {
  fmt.Println("Password correct")
} else {
  fmt.Println("Password wrong")
}
```
A more elaborate example exists in [play.go](https://github.com/FabianWe/gopherbounce/blob/master/cmd/play/play.go)

## Using different hash / key functions
There are three algorithms implemented. Each algorithm implements the [Hasher](https://godoc.org/github.com/FabianWe/gopherbounce#Hasher) interface. Implemented algorithms currently include [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt), [scrypt](https://godoc.org/golang.org/x/crypto/scrypt) and [argon2](https://godoc.org/golang.org/x/crypto/argon2) (argon2i and argon2id). Each of them has an implementation wrapping it, for example [ScryptHasher](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptHasher).  These hashers can be created with an algorithm specific config ([NewScryptHasher](https://godoc.org/github.com/FabianWe/gopherbounce#NewScryptHasher) with a [ScryptConf](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptConf)). The New functions usually accept `nil` and create some sane defaults. Change those values only if you know what you're doing! For example: `ScryptHasher` by default creates keys and salts of length 64. If you want a length of 32 you can do:
```go
hasher := gopherbounce.NewScryptHasher(nil)
hasher.KeyLen = 32
```
For all parameters check the code documentation on [GoDoc](https://godoc.org/github.com/FabianWe/gopherbounce). A list of default parameters can be found below.
There are instances of all [Hashers with sane default parameters](https://godoc.org/github.com/FabianWe/gopherbounce#pkg-variables): `gopherbounce.Bcrypt`, `gopherbounce.Scrypt`, `gopherbounce.Argon2i` and `gopherbounce.Argon2id`. You can use these hashers without creating new Hasher instances by yourself. There is also a `gopherbounce.DefaultHasher` which can be used if you have no idea which algorithm you should use. The current default hasher is [argon2id](https://en.wikipedia.org/wiki/Argon2). Argon2 is the winner of the [Password Hashing Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition) in July 2015. You should never change the parameters of these default hashers, that could be confusing. Instead use their `Copy` functions or create new ones with `nil` as the conf parameter as shown above.

## Which hash function should I use?
bcrypt, scrypt and argon2id should all be fine. bcrypt is very often used and should be fine. Argon2id is the winner of the [Password Hashing Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition) in July 2015. So it's not very old and not in use for a long time (like bcrypt), thus has received less scrutiny. argon2id is the default in this package though, I like how argon2id scales even for further hardware improvements.
So in short: bcrypt is fine and often used and thus battle-tested. argon2id seems very good and scales nicely. scrypt should be fine as well, argon2i should not be used, in constrast to argon2id. argon2id has the big advantage that it scales nicely (with both time and memory).

## Validating hashes
The easiest way to validate hashes is to use [GuessValidatorFunc](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidatorFunc) or [GuessValidator](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidator). They both accept the hashed version of a password and return either a function that can compare passwords with the hashed entry or a [Validator](https://godoc.org/github.com/FabianWe/gopherbounce#Validator) object. See the documentation for more details.

## Parsing hashes
The password hashes are encoded in a single string and there are functions to parse these hash strings. For example scrypt may produce the following string: ` $scrypt$ln=17,r=8,p=1$iDXJYV9jfWJVxmT7WxJvQ36G+gstxkYaapud/VfyZNs$Fknczp5AEqM6AwehE6D6VtV2lk/6gUNHM311ICEMkrE`. This contains all parameters as well as the key and salt (encoded with base64). This string can be parsed with [ParseScryptData](https://godoc.org/github.com/FabianWe/gopherbounce#ParseScryptData). Similar functions exist for other hashers as well. This is exactly what is done by the Validator implementations by the way.

## How to embed into an application
There are some basic rules on how to store user passwords. I'm not a security expert, that should be said for the whole library! I did my best to make everything secure, but that's not a promise! So here's a short recap on how to deal with passwords:

 1. Never store the password in clear text, always store hashed versions (as computed by a Hasher)
 2. Store these hashes in a database or in a file. Hashers return `[]byte` and these can be converted to a `string` with `string(hashed)`
 3. When a user tries to login: Retrieve the stored hashed string, use [GuessValidatorFunc](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidatorFunc) or [GuessValidator](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidator) to compare the hashed version with a clear text password
 4. Only if the returned error is `nil` accept the password. If any error is returned (no matter which one) assume that the login failed. Check the different errors in the documentation for more details
5. Use a minimum password length that is always checked on the server-side in web applications
6. All implemented algorithms compute a cryptographically secure salt and include this salt in the encoding
7. If you ever have to compare raw keys by yourself, never compare them by iterating over all entries. Always use a constant time compare function such as [subtle/ConstantTimeCompare](https://golang.org/pkg/crypto/subtle/#ConstantTimeCompare)

## Default Parameters
This section describes the current default parameter values of the hashers. The cost parameters are rather high compared to the proposed defaults of the algorithms. Since the documentations are usually some years old I think it's a good idea to increase the parameters. I've tried to reach 241ms computation time for each hash computation.

### bcrypt
Read details in the [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) documentation.

| Parameter | Default | Note                             |
|-----------|---------|----------------------------------|
| Cost      | 12      | Must be a value between 4 and 31 |

The cost parameter can be increased to make the computation more expensive. The default cost is set to 12, in contrast to the bcrypt package which uses 10. This is due to better hardware performance as of today.

### scrypt
Read the details in the [scrypt](https://godoc.org/golang.org/x/crypto/scrypt) documentation. More details can be found [here](https://blog.filippo.io/the-scrypt-parameters/).

| Parameter | Default        | Note                        |
|-----------|----------------|-----------------------------|
| N         | 65536  (= 2¹⁶) | CPU / memory cost parameter |
| R         | 8              | r * p < 2³⁰                 |
| P         | 1              | r * p < 2³⁰                 |
| KeyLen    | 64             |                             |

N is the main CPU / memory cost parameter. The scrypt package documentation recommends N = 32768 (2¹⁵). However I've found that to small due to improved hardware, thus the default is 65536 (2¹⁶). However note that N scales both CPU and memory, on systems with restricted memory (maybe even some servers with lots of hash computations) 2¹⁶ can be too much. I really prefer argon2.

Note that N is the cost parameter (as can be found in the documentation). N must be a power of two. You can't set n directly, instead you can set the number of rounds with N = 2^(rounds). So for a value of N = 65536 do `SetRounds(16)`. For invalid rounds (2^(rounds) overflows int) rounds = 16 will used and a warning gets logged. Just use rounds s.t. 2^rounds fits in an integer.

## Argon2i
Read the details in the [argon2](https://godoc.org/golang.org/x/crypto/argon2) documentation.

| Parameter | Default        | Note                  |
|-----------|----------------|-----------------------|
| Time      | 5              | CPU cost parameter    |
| Memory    | 64*1024 ~64 MB | Memory in KiB         |
| Threads   | Number of CPUs | Concurrency parameter |
| KeyLen    | 64             |                       |

The documentation suggests Time (t) = 3 and Memory (m) = 32 * 1024 ~32 MB, this is not enough in my opinion so both have been increased.

## Argon2id
Read the details in the [argon2](https://godoc.org/golang.org/x/crypto/argon2) documentation.

| Parameter | Default        | Note                  |
|-----------|----------------|-----------------------|
| Time      | 5              | CPU cost parameter    |
| Memory    | 64*1024 ~64 MB | Memory in KiB         |
| Threads   | Number of CPUs | Concurrency parameter |
| KeyLen    | 64             |                       |

The documentation suggests Time (t) = 1. Again this parameter has been increased.

### Auto tuning
In order to automatically compute cost parameters for the algorithms there are four auto tuning functions:

 1. [TuneBcrypt](https://godoc.org/github.com/FabianWe/gopherbounce#TuneBcrypt): Tunes the cost parameter
 2. [TuneScrypt](https://godoc.org/github.com/FabianWe/gopherbounce#TuneScrypt): Tunes the N parameter, all other parameters are left unchanged
 3. [TuneArgon2i](https://godoc.org/github.com/FabianWe/gopherbounce#TuneArgon2i): Tunes the Time parameter, all other parameters are left unchanged
 4. [TuneArgon2id](https://godoc.org/github.com/FabianWe/gopherbounce#TuneArgon2id): Tunes the Time parameter, all other parameters are left unchanged

However you should not use these methods in your software to automatically compute your parameters! Run the functions, check the parameters and draw your own conclusions.

There is also a small tool `tune` in [cmd/tune/tune.go](https://github.com/FabianWe/gopherbounce/blob/master/cmd/tune/tune.go).
Example usage: `./tune scrypt 241ms`. This will compute the scrypt conf with increasing N values until at least an average of 241ms per computation is reached.

## Hash sizes
The computed hashes contain the parameters as well as the key (encoded base64) and the salt (same length as the key, also encoded base64). To store hashes in a database a `VARCHAR` with a big enough size should be used. Here is a list of the max encoding length (not guaranteed to be correct, but should be fine).

| Algorithm | KeyLen     | Max Encoding length |
|-----------|------------|---------------------|
| bcrypt    | 32 (fixed) | 60                  |
| scrypt    | 32         | 149                 |
| scrypt    | 64         | 237                 |
| argon2i   | 32         | 153                 |
| argon2i   | 64         | 241                 |
| argon2id  | 32         | 154                 |
| argon2id  | 64         | 242                 |

## Constraints
Constraints impose restrictions on the arguments of hashers. That is if a password hash was created with values that now became insecure (better hardware or whatever) or with a hashing algorithm that proved to be insecure these password hashes should be replaced. gopherbounce has a [Constraint](https://godoc.org/github.com/FabianWe/gopherbounce#Constraint) interface for this purpose.

There are several implementations of this interface, here are their usecases:

 - Filter by algorithm: If you used bcrypt all the time but now you think that bcrypt is not safe enough any more use an [AlgConstraint](https://godoc.org/github.com/FabianWe/gopherbounce#AlgConstraint). For example `gopherbounce.NewAlgConstraint(gopherbounce.BcryptAlg)`. This will create a constraint that returns true for all bcrypt hashes.
 - Filter by algorithm parameters: If you want to find all scrypt hashes that were created with N < 32768 you can use [ScryptConstraint](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptConstraint). This type does not implement the `Constraint` interface directly but implements instead [AbstractScryptConstraint](https://godoc.org/github.com/FabianWe/gopherbounce#AbstractScryptConstraint).  To create the constraint mentioned above use `gopherbounce.NewScryptConstraint(32768, "N", gopherbounce.Less)`. To use it directly as a `Constraint` you can use `MultiConstraint` as explained below. There are also algorithm specific constraints for the other algorithms: [BcryptConstraint](https://godoc.org/github.com/FabianWe/gopherbounce#BcryptConstraint) and [Argon2Constraint](https://godoc.org/github.com/FabianWe/gopherbounce#Argon2Constraint) (for both argon2i and argon2id).
 - Accumulate algorithm specific constraints: If you want a constraint for scrypt that checks if N < 32768 or r < 8 you can build a disjunction of these two constraints:
 ```go
c1 := gopherbounce.NewScryptConstraint(32768, "N", gopherbounce.Less)
c2 := gopherbounce.NewScryptConstraint(8, "r", gopherbounce.Less)
c := gopherbounce.NewScryptAcc(gopherbounce.Disjunction, c1, c2)
 ```

 - An [ScryptAcc](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptAcc)  can be used to combine different scrypt constraints. In this case we create a disjunction. That is if either one of the constraints is true the disjunction is true. `ScryptAcc` itself again implements `AbstractScryptConstraint`. Again there are accumlators for other algorithms: [BcryptAcc](https://godoc.org/github.com/FabianWe/gopherbounce#BcryptAcc),  [Argon2iAcc](https://godoc.org/github.com/FabianWe/gopherbounce#Argon2iAcc),  [Argon2idAcc](https://godoc.org/github.com/FabianWe/gopherbounce#Argon2idAcc)
 - Use a [MultiConstraint](https://godoc.org/github.com/FabianWe/gopherbounce#MultiConstraint) to use algorithm specific constraints as a general `Constraint`. `MultiConstraint` implements the general `Constraint` interface and performs tests for specific algorithms. See the godoc for more details. It can be used to "convert" an algorithm specific constraint to a general `Constraint`. The example below demonstrates this: The `Check` method of the `MultiConstraint` returns true for all bcrypt hashes and all scrypt hashes where N < 32768 or r < 8:
```go
multi := gopherbounce.NewMultiConstraint()
s1 := gopherbounce.NewScryptConstraint(32768, "N", gopherbounce.Less)
s2 := gopherbounce.NewScryptConstraint(8, "r", gopherbounce.Less)
s := gopherbounce.NewScryptAcc(gopherbounce.Disjunction, s1, s2)
// ignore bcrypt
multi.AddAlgConstraint(gopherbounce.BcryptAlg)
// set scrypt constraint
multi.ScryptConstraint = s
```
 - Multiple `Constraint`s can be combined in a [disjunction](https://godoc.org/github.com/FabianWe/gopherbounce#ConstraintDisjunction) or [conjunction](https://godoc.org/github.com/FabianWe/gopherbounce#ConstraintConjunction).
 - Note that whenever we use a conjunction ([ConstraintConjunction](https://godoc.org/github.com/FabianWe/gopherbounce#ConstraintConjunction) or one of the algorithm specific accumulators) the empty conjunction always returns true.
### Parsing constraints
You can also parse constraints from a file (or any reader) with [ParseConstraints](https://godoc.org/github.com/FabianWe/gopherbounce#ParseConstraints) or [ParseConstraintsFromFile](https://godoc.org/github.com/FabianWe/gopherbounce#ParseConstraintsFromFile). Here is a small example (the values must not really make sense, it's just a syntax example):
```
[bcrypt]
Cost < 12

[scrypt = foo]
KeyLen < 12
R <= 9

ignore bcrypt

[argon2i = bar]
Time < 4
Memory = 2

[argon2id]
Time < 10
KeyLen = 32
```
As you can see there are different blocks and constraints for that block. For example "[scrypt]" followed by constraints for scrypt. Blocks must be separated by  at least one blank line. Instead of a line of the form "[ALG]" a line of the form "ignore ALG" is accepted, for example "ignore bcrypt". The meaning is that bcrypt should be ignored completely.  This function returns all parsed constraints in form of the collection type [ConstraintsCol](https://godoc.org/github.com/FabianWe/gopherbounce#ConstraintsCol). The form "[argon2i = bar]" is a named block. Though this is syntactically correct the names are ignored by the parse method.

Whatever you do with the result: The bcrypt constraint "Cost < 12" should be useless because "ignore bcrypt" completely ignores bcrypt. Again, just a syntax example.

The workflow with constraints should be as follows:

 1. User tries to log in
 2. If password is correct try the validator on the hash
 3. If validator returns true: Compute new hash (with a more secure hasher) and store the new hash

## License
Copyright 2018, 2019 Fabian Wenzelmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The following external packages are imported:

 - Golang standard library
 - [golang/crypto](https://github.com/golang/crypto),

[golang/crypto](https://github.com/golang/crypto), comes with the following license:
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
