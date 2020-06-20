package main

import (
	"log"

	"github.com/purnaresa/bulwark/encryption"
	"github.com/purnaresa/bulwark/utils"
)

func main() {
	image := utils.ReadFile("test.jpg")

	encryptionClient := encryption.NewClient()
	secret := encryptionClient.GenerateRandomString(32)
	cipherImage := encryptionClient.EncryptAES(image, []byte(secret))

	err := utils.WriteFile(cipherImage, "test-encrypted")
	if err != nil {
		log.Fatalln(err)
	}

	encryptedImage := utils.ReadFile("test-encrypted")
	plainImage := encryptionClient.DecryptAES(encryptedImage, []byte(secret))
	err = utils.WriteFile(plainImage, "test-original.jpg")
	if err != nil {
		log.Fatalln(err)
	}
}
