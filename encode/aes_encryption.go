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

// vi. Convert the encrypted value to Hex and ensure TAG value is incorporated. i.e.

// byteToHex(CIPHER+TAG). Some programming languages like Java by default append TAG value so, in such cases directly convert the cipher text to hex value.

// vii. Append the Hex value of IV create on Step ii.

// viii. Pass the encrypted value to SmartPay Application. So, the encrypted value should be like following:

// ENC_REQUEST = Hex(IV) + Hex(Cipher+Tag)

// ix. Following is sample step wise output for help in programming

// PLAIN_TEXT = “Hello World”
// WORKING_KEY = “secretKey12345678998765432112345”
// RANDOM_IV_HEX = “d99c56fd684cb7ca1a3cd2c73037482c”
// CIPHERTEXT (with Tag) HEX VALUE = 1d0476a660c926b2d5ff80a7813fdc91d41e5bedebe9c4499899cd

// ENC_REQUEST (IV HEX VALUE + CIPHERTEXT HEX VALUE ):
// d99c56fd684cb7ca1a3cd2c73037482c1d0476a660c926b2d5ff80a7813fdc91d41e5bedebe9c4499899cd

// x. Similarly, for decryption extract first 32 characters of encrypted string.
// xi. Convert the extracted string from Hex to Byte. This will give IV in bytes.
// xii. This IV can be used for initializing cipher block and carrying out decryption.

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
