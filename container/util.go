package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func httpGetBytes(url string) ([]byte, error) {
	r, err := httpGet(url)
	if err != nil {
		return nil, err
	}

	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func httpGetString(url string) (string, error) {
	data, err := httpGetBytes(url)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func httpGet(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", fmt.Sprintf("rootca/%s (github.com/tlsinspector/rootca)", Version))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	return resp.Body, nil
}

func makeP7BFromCerts(certPaths []string, p7bPath string) error {
	args := []string{
		"crl2pkcs7",
		"-nocrl",
	}

	if len(certPaths) == 0 {
		return fmt.Errorf("no certificates to add to bundle")
	}

	for _, certPath := range certPaths {
		args = append(args, "-certfile")
		args = append(args, certPath)
	}

	args = append(args, "-out")
	args = append(args, p7bPath)

	cmd := exec.Command("openssl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl error: %s", output)
	}

	return nil
}

func writeTemp(data []byte) (string, error) {
	f, err := os.CreateTemp("", "rootca")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func downloadFile(url string, filePath string) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := httpGet(url)
	if err != nil {
		return err
	}
	defer r.Close()

	if _, err := io.Copy(f, r); err != nil {
		return err
	}

	return nil
}

func verifyCertPEMSHA(certPath string, expectedSHA256 string) bool {
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("verifyCertPEMSHA(%s): %s", certPath, err.Error())
		return false
	}
	actualSHA, err := getCertPemSHA(pemData)
	if err != nil {
		log.Printf("verifyCertPEMSHA(%s): %s", certPath, err.Error())
		return false
	}

	if expectedSHA256 != actualSHA {
		log.Printf("Bad certificate SHA. %s %s != %s", certPath, expectedSHA256, actualSHA)
		return false
	}
	return true
}

func getCertPemSHA(certData []byte) (string, error) {
	certPem, _ := pem.Decode(certData)
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return "", nil
	}

	signer := sha256.New()
	signer.Write(cert.Raw)
	return fmt.Sprintf("%X", signer.Sum(nil)), nil
}

func convertDerToPem(derPath, pemPath string) error {
	os.Remove(pemPath)
	derData, err := os.ReadFile(derPath)
	if err != nil {
		return err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derData})
	return os.WriteFile(pemPath, pemData, 0644)
}

func shaSumFile(filePath string) (string, error) {
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", h.Sum(nil)), nil
}

func extractPemCerts(data []byte) [][]byte {
	pemCerts := [][]byte{}
	pem := []byte{}
	isInCert := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()

		if bytes.Equal(line, []byte("-----BEGIN CERTIFICATE-----")) {
			isInCert = true
		}

		if isInCert {
			pem = append(pem, line...)
			pem = append(pem, byte('\n'))

			if bytes.Equal(line, []byte("-----END CERTIFICATE-----")) {
				pemCerts = append(pemCerts, pem)
				pem = []byte{}
				isInCert = false
			}
		}
	}

	return pemCerts
}

func fileExists(inPath string) bool {
	_, err := os.Stat(inPath)
	return err == nil
}
