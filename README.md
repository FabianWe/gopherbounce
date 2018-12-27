

# gopherbounce
gopherbounce is a Golang authentication framework. It bundles [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt), [scrypt](https://godoc.org/golang.org/x/crypto/scrypt) and [argon2](https://godoc.org/golang.org/x/crypto/argon2) (argon2i and argon2id) under a common interface. It provides easy to use functions for hashing and validating passwords.
Find the full code documentation on [GoDoc](https://godoc.org/github.com/FabianWe/gopherbounce).

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
There are three algorithms implemented. Each algorithm implements the [Hasher](https://godoc.org/github.com/FabianWe/gopherbounce#Hasher) interface. Implemented algorithms currently include [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt), [scrypt](https://godoc.org/golang.org/x/crypto/scrypt) and [argon2](https://godoc.org/golang.org/x/crypto/argon2) (argon2i and argon2id). Each of them has an implementation wrapping it, for example [ScryptHasher](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptHasher).  These hashers can be created with an algorithm specific config ([NewScryptHasher](https://godoc.org/github.com/FabianWe/gopherbounce#NewScryptHasher) with a [ScryptConf](https://godoc.org/github.com/FabianWe/gopherbounce#ScryptConf)). The New functions usually accept `nil` and create some sane defaults. Change those values only if you know what you're doing! For example: `ScryptHasher` by default creates keys and salts of length 32. If you want a length of 64 you can do:
```go
hasher := gopherbounce.NewScryptHasher(nil)
hasher.KeyLen = 64
```
For all parameters check the code documentation on [GoDoc](https://godoc.org/github.com/FabianWe/gopherbounce). A list of default parameters can be found below.
There are instances of all [Hashers with sane default parameters](https://godoc.org/github.com/FabianWe/gopherbounce#pkg-variables): `gopherbounce.Bcrypt`, `gopherbounce.Scrypt`, `gopherbounce.Argon2i` and `gopherbounce.Argon2id`. You can use these hashers without creating new Hasher instances by yourself. There is also a `gopherbounce.DefaultHasher` which can be used if you have no idea which algorithm you should use. The current default hasher is [argon2id](https://en.wikipedia.org/wiki/Argon2). Argon2 is the winner of the [Password Hashing Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition) in July 2015. You should never change the parameters of these default hashers, that could be confusing. Instead use their `Copy` functions or create new ones with `nil` as the conf parameter as shown above.

## Which has function should I use?
bcrypt, scrypt and argon2id should all be fine. bcrypt is very often used and should be fine. Argon2id is the winner of the [Password Hashing Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition) in July 2015. So it's not very old and not in use for a long time (like bcrypt), thus has received less scrutiny. argon2id the default in this package though, I like how argon2id scales even for further hardware improvements.
So in short: bcrypt is fine and often used and thus battle-tested. argon2id seems very good and scales nicely.

## Validating hashes
The easiest way to validate hashes is to use [GuessValidatorFunc](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidatorFunc) or [GuessValidator](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidator). They both accept the hashed version of a password and return either a function that can compare passwords with the hashed entry or a [Validator](https://godoc.org/github.com/FabianWe/gopherbounce#Validator) object. See the documentation for more details.

## Parsing hashes
The password hashes are encoded in a single string and there are functions to parse to hash strings. For example scrypt may produce the following string: `$4s$5t6drCj5zyGIx8cbf24Bhssg/deIPoIilCIhDVFe.oG=$32768$8$1$dNu7EQwUib2o0spmvj0gHb5o1DKA.lbWk03QqtA2GQC=`. This contains all parameters as well as the key and salt (encoded with base64). This string can be parsed with [ParseScryptData](https://godoc.org/github.com/FabianWe/gopherbounce#ParseScryptData). Similar functions exist for other hashers as well. This is exactly what is done by the Validator implementations by the way.

## How to embed into an application
There are some basic rules on how to store user passwords. I'm not a security expert, that should be said for the whole library! I did my best to make everything secure, but that's not a promise! So here's a short recap on how to deal with passwords:

 1. Never store the password in clear text, always store hashed versions (as computed by a Hasher)
 2. Store these hashes in a database or in a file. Hashers return `[]byte` and these can be converted to a `string` with `string(hashed)`
 3. When a user tries to login: Retrieve the stored hashed string, use [GuessValidatorFunc](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidatorFunc) or [GuessValidator](https://godoc.org/github.com/FabianWe/gopherbounce#GuessValidator) to compare the hashed version with a clear text password.
 4. Only if the returned error is `nil` accept the password. If any error is returned (no matter which one) assume that the login failed. Check the different errors in the documentation for more details
.
5. Use a minimum password length that is always checked on the server-side in web applications
6. All implemented algorithms compute a cryptographically secure salt and include this salt in the encoding
7. If you ever have to compare raw keys by yourself, never compare them by iterating over all entries. Always use a constant time compare function such as [subtle/ConstantTimeCompare](https://golang.org/pkg/crypto/subtle/#ConstantTimeCompare).

## Default Parameters
This section describes the current default parameter values of the hashers. The cost parameters are rather hight compared with the proposed defaults of the algorithms. Since the documentations are usually some years old I think it's a good idea to increase the parameters. I've tried to reach 241ms computation time for each hash computations.

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
| N         | 131072 (= 2¹⁷) | CPU / memory cost parameter |
| R         | 8              | r * p < 2³⁰                 |
| P         | 1              | r * p < 2³⁰                 |
| KeyLen    | 32             |                             |

N is the main CPU / memory cost parameter. The scrypt package documentation recommends N = 32768 (2¹⁵). However I've found that to small due to improved hardware, thus the default is 131072 (2¹⁷).

## Argon2i
Read the details in the [argon2](https://godoc.org/golang.org/x/crypto/argon2) documentation.

| Parameter | Default        | Note                  |
|-----------|----------------|-----------------------|
| Time      | 10             | CPU cost parameter    |
| Memory    | 64*1024 ~64 MB | Memory in KiB         |
| Threads   | Number of CPUs | Concurrency parameter |
| KeyLen    | 32             |                       |

The documentation suggests Time (t) = 3 and Memory (m) = 32 * 1024 ~32 MB, this is not enough in my opinion so both have been increased.

## Argon2id
Read the details in the [argon2](https://godoc.org/golang.org/x/crypto/argon2) documentation.

| Parameter | Default        | Note                  |
|-----------|----------------|-----------------------|
| Time      | 10             | CPU cost parameter    |
| Memory    | 64*1024 ~64 MB | Memory in KiB         |
| Threads   | Number of CPUs | Concurrency parameter |
| KeyLen    | 32             |                       |

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
| scrypt    | 32         | 156                 |
| scrypt    | 64         | 244                 |
| argon2i   | 32         | 182                 |
| argon2i   | 64         | 270                 |
| argon2id  | 32         | 183                 |
| argon2id  | 64         | 271                 |

## License
Copyright 2018 Fabian Wenzelmann

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
