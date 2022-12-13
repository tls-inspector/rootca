package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func httpGetString(url string) (string, error) {
	r, err := httpGet(url)
	if err != nil {
		return "", err
	}

	defer r.Close()
	data, err := io.ReadAll(r)
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
		return false
	}
	_, derData := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return false
	}

	signer := sha256.New()
	signer.Write(cert.Raw)
	actualSHA := fmt.Sprintf("%X", signer.Sum(nil))

	return expectedSHA256 == actualSHA
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
