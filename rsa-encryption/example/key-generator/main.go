package main

import (
	"io/ioutil"
	"log"

	"github.com/purnaresa/bulwark/rsa-encryption"
)

func main() {
	_, _, privateKey, publicKey, err := rsa.GenerateKeyPairInPEM()
	if err != nil {
		log.Fatalln(err)
		return
	}

	err = ioutil.WriteFile("private-key.pem", privateKey, 0644)
	if err != nil {
		log.Fatalln(err)
		return
	}

	err = ioutil.WriteFile("public-key.pem", publicKey, 0644)
	if err != nil {
		log.Fatalln(err)
		return
	}
}
