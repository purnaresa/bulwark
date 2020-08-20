package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
)

func SignDefault(plaintext, privateKey []byte) (signature string, err error) {
	client, err := New(privateKey, nil)
	if err != nil {
		log.Println(err)
		return
	}
	signatureByte, err := client.Sign(plaintext)
	if err != nil {
		log.Println(err)
		return
	}
	signature = base64.StdEncoding.EncodeToString(signatureByte)
	return
}

func VerifyDefault(plaintext, publicKey []byte, signature string) (err error) {
	publicKeys := make(map[string][]byte)
	publicKeys["default"] = publicKey
	client, err := New(nil, publicKeys)
	if err != nil {
		log.Println(err)
		return
	}

	signatureByte, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Println(err)
		return
	}

	err = client.Verify(plaintext, signatureByte, "default")
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func (c *Client) Sign(plaintext []byte) (signature []byte, err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(plaintext)
	hashed := pssh.Sum(nil)
	signature, err = rsa.SignPSS(
		rand.Reader,
		c.PrivateKey,
		newhash,
		hashed,
		&opts,
	)
	return
}

func (c *Client) Verify(plaintext, signature []byte, target string) (err error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(plaintext)
	hashed := pssh.Sum(nil)
	err = rsa.VerifyPSS(
		c.PublicKeys[target],
		newhash,
		hashed,
		signature,
		&opts,
	)
	return
}
