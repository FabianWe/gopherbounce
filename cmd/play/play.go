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
	hash, err := gopherbounce.Argon2id.Generate("Foo")
	// hash, err := gopherbounce.Scrypt.Generate("Bar")
	if err != nil {
		panic(err)
	}
	data, parseErr := gopherbounce.ParseArgon2idData(hash)
	// data, parseErr := gopherbounce.ParseScryptData(hash)
	if parseErr != nil {
		panic(parseErr)
	}
	// fmt.Println("conf:", data.ScryptConf)
	fmt.Println("data:", data)
	fmt.Println(data.Argon2Conf)
	// fmt.Println("Real key len:", len(data.RawKey))
}
