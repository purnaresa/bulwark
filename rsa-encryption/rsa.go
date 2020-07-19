package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

type Client struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func NewClient(private *rsa.PrivateKey, public *rsa.PublicKey) (client *Client) {
	client = &Client{
		Private: private,
		Public:  public,
	}
	return
}

func (c *Client) Encrypt(plainData []byte) (cipherData []byte, err error) {

	hash := sha256.New()
	cipherData, err = rsa.EncryptOAEP(
		hash,
		rand.Reader,
		c.Public,
		[]byte(plainData),
		[]byte(""),
	)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func (c *Client) EncryptToBase64(plainData []byte) (cipherData string, err error) {
	cipherDataByte, err := c.Encrypt(plainData)
	if err != nil {
		return
	}
	cipherData = base64.StdEncoding.EncodeToString(cipherDataByte)
	return
}

func (c *Client) Decrypt(cipherData []byte) (plainData []byte, err error) {
	hash := sha256.New()
	plainData, err = rsa.DecryptOAEP(
		hash,
		rand.Reader,
		c.Private,
		cipherData,
		[]byte(""),
	)
	if err != nil {
		log.Println(err)
		return
	}
	return

}

func (c *Client) DecryptToString(cipherData []byte) (plainData string, err error) {
	plainDataByte, err := c.Decrypt(cipherData)
	if err != nil {
		return
	}
	plainData = string(plainDataByte)
	return
}
