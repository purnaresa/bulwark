package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type Client struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
}

func New(privateKey []byte, publicKeys map[string][]byte) (client *Client, err error) {
	client = &Client{}

	if privateKey != nil {
		validPrivateKey, errPrivate := x509.ParsePKCS1PrivateKey(privateKey)
		if errPrivate != nil {
			err = errPrivate
			log.Println(err)
			return
		}
		client.PrivateKey = validPrivateKey
	}

	if publicKeys != nil {
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
		client.PublicKeys = validPublicKeysMap
	}

	return
}
