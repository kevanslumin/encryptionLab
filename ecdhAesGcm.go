package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"

	"fmt"
)

func main() {
	var err error

	fmt.Printf("--ECC Parameters--\n")
	fmt.Printf(" Name: %s\n", elliptic.P256().Params().Name)
	fmt.Printf(" N: %x\n", elliptic.P256().Params().N)
	fmt.Printf(" P: %x\n", elliptic.P256().Params().P)
	fmt.Printf(" Gx: %x\n", elliptic.P256().Params().Gx)
	fmt.Printf(" Gy: %x\n", elliptic.P256().Params().Gy)
	fmt.Printf(" Bitsize: %x\n\n", elliptic.P256().Params().BitSize)

	random := make([]byte, 32)
	rand.Read(random)
	fmt.Printf(" Random Number: %x\n\n", string(random))

	priva, _ := ecdh.P256().GenerateKey(rand.Reader)
	puba := priva.PublicKey()

	fmt.Printf("\nYour private key %x", priva.Bytes())
	fmt.Printf("\nYour public key %x\n", puba.Bytes())

	fmt.Printf("Your public Key formatted for echo:\n")
	fmt.Printf("echo -ne \"%s\" > /tmp/fifo\n\n", ConvertBytesToEchoFormat(puba.Bytes()))

	reader := bufio.NewReader(os.Stdin)
	goodKey := false
	serverPublicKeyText := ""
	pubbbytes := make([]byte, 65)

	for !goodKey {
		goodKey = true
		fmt.Print("\n\nEnter peer public key in hex: ")
		serverPublicKeyText, err = reader.ReadString('\n')
		if err != nil {
			goodKey = false
			fmt.Printf("\nCould not read peer public key: %v", err)
			continue
		}
		serverPublicKeyText = strings.TrimSpace(serverPublicKeyText)

		// The first byte is always 0x04 to denote the key is uncompressed
		if len(serverPublicKeyText) != 130 {
			goodKey = false
			fmt.Println("\nKey should be 65 hex digits, try again.")
			continue
		}

		pubbbytes, err = hex.DecodeString(serverPublicKeyText)
		if err != nil {
			goodKey = false
			fmt.Println("\nCould not parse peer public key, try again.")
			continue
		}
	}

	pubb, _ := ecdh.P256().NewPublicKey(pubbbytes)

	shared, err := priva.ECDH(pubb)
	if err != nil {
		log.Fatalf("\nUnable to derive shared secret: %v", err)
	}

	fmt.Printf("\nShared key %x\n\n", shared)

	block, err := aes.NewCipher(shared)
	if err != nil {
		log.Fatalf("\nUnable to create a new aes encryption key from shared secret: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("\nUnable to create a new GCM: %v", err)
	}

	fmt.Print("\n\nBegin a line with e to encrypt or d to decrypt: \n")
	for {

		userInput, err := reader.ReadString('\n')
		if err != nil {
			fmt.Print("\n\nBegin a line with e to encrypt or d to decrypt: \n")
			continue
		}
		if userInput[0] == 'e' {
			message := userInput[2:]

			// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
			nonce := make([]byte, 12)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				log.Fatalf("\nUnable to create a nonce: %v", err)
			}

			ciphertext := aesgcm.Seal(nil, nonce, []byte(message), nil)

			// transmit the nonce at the front of the ciphertext
			noncePlusCiphertext := append(nonce, ciphertext...)
			fmt.Printf("\nEncrypted message: %x\n\n", noncePlusCiphertext)

			fmt.Printf("Encrypted message formatted for echo:\n")
			fmt.Printf("echo -ne \"%s\" > /tmp/fifo\n\n", ConvertBytesToEchoFormat(ciphertext))
			continue
		} else if userInput[0] == 'd' {

			noncePlusCiphertext, _ := hex.DecodeString(userInput[2:])

			// The nonce is at the front of the ciphertext
			nonce := noncePlusCiphertext[:12]
			ciphertext := noncePlusCiphertext[12:]
			message := make([]byte, len(noncePlusCiphertext[12:]))
			message, err := aesgcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				fmt.Printf("\nUnable to decrypt message: %v", err)
				fmt.Print("\n\nBegin a line with e to encrypt or d to decrypt: \n")
				continue
			}

			fmt.Printf("Decrypted message: %s\n", message)
		} else {
			fmt.Print("\n\nBegin a line with e to encrypt or d to decrypt: \n")
			continue
		}

	}

}

func ConvertBytesToEchoFormat(input []byte) string {
	echoMessage := []byte(hex.EncodeToString(input))
	// add in \x before every byte so we can use it in echo
	for i := 0; i < len(echoMessage); i += 4 {
		echoMessage = append(echoMessage[:i+2], echoMessage[i:]...)
		echoMessage[i] = 92    // backslash char
		echoMessage[i+1] = 120 // x char
	}

	return string(echoMessage)
}
