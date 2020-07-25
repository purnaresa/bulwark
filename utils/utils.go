package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
)

func ReadFile(filename string) (content []byte) {
	filepath := fmt.Sprintf("%s", filename)
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Fatal(err.Error())
	}
	return
}

func WriteFile(content []byte, filename string) (err error) {
	filepath := fmt.Sprintf("%s", filename)

	err = ioutil.WriteFile(filepath, content, 0644)
	if err != nil {
		return
	}
	return
}

func ReadPublicKeyFile(filepath string) (publicKey *rsa.PublicKey, err error) {
	pubPEM, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}
	publicKey, err = ReadPublicKey(pubPEM)
	return
}

func ReadPublicKey(publicKeyData []byte) (publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		err = errors.New("failed to parse PEM block containing the key")
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKey = pub
	default:
		err = errors.New("failed to parse the file to Public Key")
	}
	return
}

func ReadPrivateKeyFile(filepath string) (privateKey *rsa.PrivateKey, err error) {
	privPEM, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}
	privateKey, err = ReadPrivateKey(privPEM)
	return
}

func ReadPrivateKey(privateKeyData []byte) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		err = errors.New("failed to parse PEM block containing the key")
		return
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	return
}
