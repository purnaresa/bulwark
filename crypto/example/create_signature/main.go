package main

import (
	"log"

	"github.com/purnaresa/bulwark/crypto"
)

func main() {
	// provision key pair
	// In production environment, RSA key pair is provisioned off the system.
	// You must store the private key in secure place. Holistically - if your private key is leaked,
	// the signature is flawed because the signature cannot guarantee it authenticity.
	// The public key should be shared to the partner that communicating with you.
	// If your private key is leaked, generate new key pair!
	privateKey, publicKey, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalln(err)
	}

	// create dummy plaintext
	// You can encrypt anything as long as it is in byte format.
	// The important thing is the size of the plaintext.
	// RSA only able to encrypt limited size of plaintext.
	// It will be enough for most case when encrypting a text message.
	// If you need to encrypt big sized data like an image or pdf, use double encryption approach.
	// First, you encrypt the file with a random generated key using AES/symmetrical.
	// Then you encrypt the generated key using RSA.
	plaintext := []byte("hello, my name is plaintext")
	log.Printf("plaintext : %s\n\n", string(plaintext))

	// create signature
	// Sign the plaintext with a private key.
	// The output is signature that can be verified using the public key from the key pair.
	// The signature is created using randomiser. The signature will be different each time even the plaintext is the same.
	// The use case for create a signature is right before sending the data to your partner along with the signature.
	// If your application is handling Personally identifiable information (PII) you will need to encrypt the data.
	// Create signature based on plaintext before encryption.
	// If you create the signature after encryption, attacker may sabotage (modify) the signature so the verification failed,
	// therefore the information is not processed. Protect the information by encrypt both ciphertext and signature.
	log.Println("creating signature...")
	signature, err := crypto.SignDefault(plaintext, privateKey)
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Printf("signature : %s\n\n", string(signature))
	}

	// verify signature
	// Signature must be verified using the public key of signature creator.
	// The plaintext is required material to check whatever the signature is valid or not.
	// If the verification failed, it will return with error object.
	// In production scenario, the one that verifying the signature is the partner that you are communicating with.
	// So you must share your public key to them for they to verify the signature.
	log.Println("verifying signature and plaintext...")
	errVerify := crypto.VerifyDefault(plaintext, publicKey, signature)
	if errVerify != nil {
		log.Fatalln(errVerify)
	} else {
		log.Println("verification success!")
	}

}
