package main

import (
	"fmt"
	"crypto/rand"

	"github.com/emmansun/gmsm/sm2"
)

func main() {
    jbt_test()
}

func jbt_test() {
	// plain_text := "作业太多了写不完1\n作业太多了写不完2\n作业太多了写不完3\n作业太多了写不完4\n作业太多了写不完5\n作业太多了写不完6\n作业太多了写不完7\n"
	 plain_text := "12345\n"
	for i := 0; i < 100; i++ {
        priv, _ := sm2.GenerateKey(rand.Reader)
		// fmt.Println(priv.D)
		ciphertext, _ := sm2.Encrypt(rand.Reader, &priv.PublicKey, []byte(plain_text), sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C2C3))
		// fmt.Println(ciphertext)

		re_plain_text, _ := priv.Decrypt(rand.Reader, ciphertext, sm2.NewPlainDecrypterOpts(sm2.C1C2C3))
		fmt.Println(string(re_plain_text))

		if plain_text != string(re_plain_text) {
			fmt.Println("Panic")
			break
		} else {
			fmt.Println("Eq")
		}
    }

	

	
}
