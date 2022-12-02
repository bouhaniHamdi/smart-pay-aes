package main

import (
	"fmt"
	"smart-pay-aes/encode"
)

func main() {

	ciphertext, _, err := encode.GenerateEncryptedValuePlainText("exampleplaintext", "secretKey12345678998765432112345")
	if err != nil {
		panic(err)
	}

	fmt.Println(ciphertext)
}
