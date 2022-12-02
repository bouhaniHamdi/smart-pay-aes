package encode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// In case if merchant is using any other programming language, AES Encryption can be developed on basis of following information:
// 	    a) Algorithm Used: AES 256/GCM/NoPadding
// 		b) Initialization Vector (IV): 16 bytes
// 		c) Tag Length: 16 bytes

// Following is a sample step-wise output:

// i. Assuming Working Key as WK = “secretKey12345678998765432112345”

// ii. Create Initialization Vector (IV) of random 16 bytes.

// iii. Generate secret key by converting Working Key (in step i) into bytes.

// iv. Get Cipher instance of as AES 256 GCM with No Padding (RAW).

// v. Generate encrypted value of Plain Text.



func GenerateEncryptedValuePlainText(plainText, key string) ([]byte, []byte, error) {
	plainTextBytes := []byte(plainText)

	// Assuming Working Key
	// Create Initialization Vector (IV) of random 16 bytes.
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, nil, err
	}

	// Get Cipher instance of as AES 256 GCM with No Padding (RAW).
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Generate secret key by converting Working Key (in step i) into bytes.
	// AES-GCM provides confidentiality, integrity, and authentication. To provide the last two, one needs an authentication tag.
	// The 16-byte tag size is always calculated, and in your case it is appended.
	size := aesgcm.NonceSize()
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Generate encrypted value of Plain Text.
	ciphertext := aesgcm.Seal(nil, nonce, plainTextBytes, nil)

	fmt.Printf("\nKey:\t\t%x", key)
	fmt.Printf("\nCiphertext:\t%x \n\n", ciphertext)

	return ciphertext, nonce, nil
}
