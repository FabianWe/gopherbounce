package main

import (
	"fmt"
	"strings"

	"github.com/FabianWe/gopherbounce"
	"golang.org/x/crypto/argon2"
)

func main() {
	test(gopherbounce.Bcrypt)
	test(gopherbounce.Scrypt)
	test(gopherbounce.Argon2i)
	test(gopherbounce.Argon2id)
	fmt.Println(strings.Repeat("#", 10))
	foo()
}

func test(hasher gopherbounce.Hasher) {
	hash, err := hasher.Generate("password")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
}

func foo() {
	salt, saltErr := gopherbounce.GenSalt(32)
	if saltErr != nil {
		panic(saltErr)
	}
	key := argon2.Key([]byte("foo"), salt, 3, 32*1024, 4, 32)
	fmt.Println(string(gopherbounce.Base64Encode(key)))
	fmt.Println(strings.Repeat("-", 10))
	key = argon2.Key([]byte("foo"), salt, 3, 32*1024, 4, 32)
	fmt.Println(string(gopherbounce.Base64Encode(key)))
}
