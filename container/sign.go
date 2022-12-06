package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func signFile(filePath string) error {
	privKeyStr := os.Getenv("ROOTCA_SIGNING_PRIVATE_KEY")
	if privKeyStr == "" {
		return nil
	}
	privKeyStr = strings.ReplaceAll(privKeyStr, "\\n", "\n")

	pubKeyStr := os.Getenv("ROOTCA_SIGNING_PUBLIC_KEY")
	if pubKeyStr == "" {
		return nil
	}
	pubKeyStr = strings.ReplaceAll(pubKeyStr, "\\n", "\n")

	privKeyPath, err := writeTemp([]byte(privKeyStr))
	if err != nil {
		return err
	}
	pubKeyPath, err := writeTemp([]byte(pubKeyStr))
	if err != nil {
		return err
	}

	defer os.Remove(privKeyPath)
	defer os.Remove(pubKeyPath)

	signaturePath := filePath + ".sig"

	if verifyFileSignature(filePath, signaturePath, pubKeyPath) == nil {
		log.Printf("%s signatuture OK", filePath)
		return nil
	}
	os.Remove(signaturePath)

	signArgs := []string{
		"dgst",
		"-sha256",
		"-sign",
		privKeyPath,
		"-out",
		signaturePath,
		filePath,
	}

	cmd := exec.Command("openssl", signArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl error: %s", output)
	}

	if err := verifyFileSignature(filePath, signaturePath, pubKeyPath); err != nil {
		os.Remove(signaturePath)
		return fmt.Errorf("signature validation failed after signing: %s", err.Error())
	}

	log.Printf("%s signatuture OK", filePath)
	return nil
}

func verifyFileSignature(filePath, signaturePath, pubKeyPath string) error {
	verifyArgs := []string{
		"dgst",
		"-sha256",
		"-verify",
		pubKeyPath,
		"-signature",
		signaturePath,
		filePath,
	}
	output, err := exec.Command("openssl", verifyArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}
	return nil
}
