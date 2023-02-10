package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func signBundle(bundleName string) error {
	if err := signFile(bundleName + ".p7b"); err != nil {
		return nil
	}
	if err := signFile(bundleName + ".pem"); err != nil {
		return nil
	}
	return nil
}

func signFile(filePath string) error {
	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("signFile: %s", err.Error())
	}

	if publicKeyBytes == nil || privateKeyBytes == nil {
		return nil
	}

	privKeyPath, err := writeTemp(privateKeyBytes)
	if err != nil {
		return err
	}
	pubKeyPath, err := writeTemp(publicKeyBytes)
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

	cmd := exec.Command(opensslPath, signArgs...)
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
	output, err := exec.Command(opensslPath, verifyArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}
	return nil
}
