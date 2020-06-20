package utils

import (
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
