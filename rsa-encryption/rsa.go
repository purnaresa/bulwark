package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
)

type Client struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
}

func New(privateKey []byte, publicKeys map[string][]byte) (client *Client, err error) {
	validPrivateKey, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		log.Println(err)
		return
	}

	validPublicKeysMap := make(map[string]*rsa.PublicKey)
	for k, v := range publicKeys {
		validPublicKey, errPublic := x509.ParsePKIXPublicKey(v)
		if errPublic != nil {
			err = errPublic
			log.Println(err)
			return
		}
		switch validPublicKey := validPublicKey.(type) {
		case *rsa.PublicKey:
			validPublicKeysMap[k] = validPublicKey
		default:
			err = errors.New("Invalid Public Key Type")
			log.Println(err)
			return
		}
	}
	client = &Client{
		PrivateKey: validPrivateKey,
		PublicKeys: validPublicKeysMap,
	}
	return
}

func EncryptDefault(plainData, publicKey []byte) (cipherData string, err error) {
	publicKeys := make(map[string][]byte)
	publicKeys["default"] = publicKey
	client, err := New(nil, publicKeys)
	if err != nil {
		log.Println(err)
		return
	}
	cipherData, err = client.EncryptToBase64(plainData, "default")
	if err != nil {
		log.Println(err)
		return
	}
	return
}

// GenerateKeyPair is a function to generate new Private and Public key pair
// The function receive no input. The output is private and public key in []byte
//
// The output is usable for immediate encryption.
// If need to store the keys, the efficient way is to use base64 format.
// It will work easily to store the keys in any kind of storage, including text file.
// Example:
// 		privatKeyB64 := base64.StdEncoding.EncodeToString(privateKeyByte)
//
// To make keys exportable; PEM format is the standart ways. Use *GenerateKeyPairInPEM* function.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	pubKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Println(err)
		return
	}
	privKey := &pubKey.PublicKey

	privateKey = x509.MarshalPKCS1PrivateKey(pubKey)
	publicKey, err = x509.MarshalPKIXPublicKey(privKey)
	if err != nil {
		log.Println(err)
	}
	return
}

// GenerateKeyPairInPEM is the extension of *GenerateKeyPair* to create key pair in PEM encoded.
// PEM is a de facto file format for storing and sending keys based on a set of 1993 IETF.
// The output is 2 pair;
// 		1. byte pair : for immediate usage and stored in internal system
// 		2. PEM encoded pair : for exporting the keys to other system
//
// Most common use case for PEM encoded pair is either write to file using *ioutil.WriteFile* or
// send the data using HTTP/ API.
func GenerateKeyPairInPEM() (privateKey, publicKey []byte, privateKeyPem, publicKeyPem []byte, err error) {
	privateKey, publicKey, err = GenerateKeyPair()
	if err != nil {
		log.Println(err)
		return
	}
	privateKeyPem = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKey,
		},
	)

	publicKeyPem = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKey,
		},
	)
	return
}

func (c *Client) Encrypt(plainData []byte, target string) (cipherData []byte, err error) {

	hash := sha256.New()
	random := rand.Reader
	cipherData, err = rsa.EncryptOAEP(
		hash,
		random,
		c.PublicKeys[target],
		plainData,
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

func (c *Client) DecryptFromBase64(cipherData []byte) (plainData []byte, err error) {
	cipherData, err = base64.StdEncoding.DecodeString(string(cipherData))
	if err != nil {
		return
	}
	plainData, err = c.Decrypt(cipherData)
	if err != nil {
		return
	}

	return
}

func (c *Client) Decrypt(cipherData []byte) (plainData []byte, err error) {
	hash := sha256.New()
	random := rand.Reader
	plainData, err = rsa.DecryptOAEP(
		hash,
		random,
		c.PrivateKey,
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
