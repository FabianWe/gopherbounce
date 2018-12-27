package main

import (
	"fmt"
	"strings"

	"github.com/FabianWe/gopherbounce"
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
	hash, err := gopherbounce.Scrypt.Generate("Foo")
	if err != nil {
		panic(err)
	}
	conf, data, parseErr := gopherbounce.ParseScrypt(hash)
	if parseErr != nil {
		panic(parseErr)
	}
	fmt.Println("conf:", conf)
	fmt.Println("data:", data)
	fmt.Println("Real key len:", len(data.RawKey))
}
