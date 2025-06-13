package main

import (
   "crypto/aes"
   "crypto/cipher"
   "crypto/rand"
   "encoding/hex"
   "fmt"
   "io"
   "os"
)

func main() {
	var data string
	fmt.Print("Enter the data to encrypt: ")
	fmt.Scanln(&data)
	plaintext := []byte(data)

	var key string
	fmt.Print("Enter a 32-byte encryption key: ")
	fmt.Scanln(&key)

	// Convert the key to a byte slice
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		fmt.Println("Key must be 32 bytes long for AES-256")
		return
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Println("Error creating AES block cipher", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error setting GCM mode", err)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("Error generating the nonce ", err)
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	enc := hex.EncodeToString(ciphertext)
	fmt.Println("Encrypted data:", enc)
	err = os.WriteFile("secret.enc", []byte(enc), 0600)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Println("Encrypted data written to secret.enc")
}