package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mathRand "math/rand"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

type Client struct{}

func NewClient() (c *Client) {
	mathRand.Seed(time.Now().UnixNano())
	c = &Client{}
	return
}

func (c *Client) EncryptAES(plainData, secret []byte) (cipherData []byte) {
	block, _ := aes.NewCipher(secret)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}

	cipherData = gcm.Seal(
		nonce,
		nonce,
		plainData,
		nil)

	return
}

func (c *Client) DecryptAES(cipherData, secret []byte) (plainData []byte) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()

	nonce, ciphertext := cipherData[:nonceSize], cipherData[nonceSize:]
	plainData, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

func (c *Client) GenerateRandomString(length int) (result string) {
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[mathRand.Intn(len(letterBytes))]
	}
	result = string(b)
	return
}
