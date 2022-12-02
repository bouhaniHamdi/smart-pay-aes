package encode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

const (
	WK = "secretKey12345678998765432112345"
)

func TestGenerateEncryptedValuePlainText(t *testing.T) {
	plainText := "Golang Programs"

	// Encrypt
	// Generate encrypted value of Plain Text.
	ciphertext, nonce, err := GenerateEncryptedValuePlainText(plainText, WK)
	if err != nil {
		t.Errorf("%v\n", err)
		t.Fail()
	}

	// Decrypt
	block, err := aes.NewCipher([]byte(WK))
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext1, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext1)
	// Output: exampleplaintext

	if plainText != string(plaintext1) {
		t.Failed()
	}

}

func TestConvertEncryptedValueToHex(t *testing.T) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.

	encryptedText, _, err := GenerateEncryptedValuePlainText("exampleplaintext", WK)
	if err != nil {
		t.Errorf("%v\n", err)
		t.Fail()
	}

	str := base64.StdEncoding.EncodeToString(encryptedText)
	fmt.Println(str)

	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		log.Fatal("error:", err)
	}

	fmt.Printf("%q\n", data)

	//ciphertext, _ := hex.DecodeString("2df87baf86b5073ef1f03e3cc738de75b511400f5465bb0ddeacf47ae4dc267d")

}
