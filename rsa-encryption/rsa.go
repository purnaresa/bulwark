package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
)

type Client struct {
	Private *rsa.PrivateKey
	Publics map[string]*rsa.PublicKey
}

func NewClient(private *rsa.PrivateKey, publics map[string]*rsa.PublicKey) (client *Client) {
	client = &Client{
		Private: private,
		Publics: publics,
	}
	return
}

func (c *Client) Encrypt(plainData []byte, target string) (cipherData []byte, err error) {

	hash := sha256.New()
	targetPubKey, valid := c.Publics[target]
	if valid == false {
		err = errors.New("target Public Key not found")
		return
	}
	cipherData, err = rsa.EncryptOAEP(
		hash,
		rand.Reader,
		targetPubKey,
		[]byte(plainData),
		[]byte(""),
	)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func (c *Client) EncryptToBase64(plainData []byte, target string) (cipherData string, err error) {
	cipherDataByte, err := c.Encrypt(plainData, target)
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
