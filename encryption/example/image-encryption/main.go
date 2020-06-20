package main

import (
	"log"

	"github.com/purnaresa/bulwark/encryption"
	"github.com/purnaresa/bulwark/utils"
)

func main() {
	// encryption start
	// step 1
	image := utils.ReadFile("original-image.jpg")

	// step 2
	encryptionClient := encryption.NewClient()
	secret := encryptionClient.GenerateRandomString(32)

	// step 3
	cipherImage := encryptionClient.EncryptAES(image, []byte(secret))

	// step 4
	err := utils.WriteFile(cipherImage, "encrypted-image")
	if err != nil {
		log.Fatalln(err)
	}
	err = utils.WriteFile([]byte(secret), "image-key.txt")
	if err != nil {
		log.Fatalln(err)
	}
	// encryption end

	// decryption start
	// 1
	encryptedImage := utils.ReadFile("encrypted-image")

	// 2
	key := utils.ReadFile("image-key.txt")

	// 3
	plainImage := encryptionClient.DecryptAES(encryptedImage, key)
	err = utils.WriteFile(plainImage, "test-original.jpg")
	if err != nil {
		log.Fatalln(err)
	}
	// decryption end
}
