package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

var githubAccessToken = os.Getenv(envGithubAccessToken)
var httpRequestUserAgent = fmt.Sprintf("rootca/%s (github.com/tlsinspector/rootca)", Version)

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

	if strings.HasPrefix(url, "https://api.github.com/") {
		if githubAccessToken != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", githubAccessToken))
		} else {
			log.Printf("Warning: no github access token specified, API requests may get rate-limited without it")
		}
	}

	req.Header.Set("User-Agent", httpRequestUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// generateBundleFromCertificates will generate a PKCS#7 and PEM bundle from the given slice of PEM certificate files
// returns the fingerprints of the PKCS#7 file, the PEM file, or an error
func generateBundleFromCertificates(pemPaths []string, bundleName string) (*BundleFingerprint, *BundleFingerprint, *BundleFingerprint, error) {
	p7bPath := bundleName + ".p7b"
	pemPath := bundleName + ".pem"
	zipPath := bundleName + ".zip"

	os.Remove(zipPath)
	zipFile, err := os.OpenFile(zipPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("zip: %s", err.Error())
	}
	zipWriter := zip.NewWriter(zipFile)

	// Sort the certificates by their hash
	certFingerprintsToPath := map[string]string{}
	certFingerprints := make([]string, len(pemPaths))
	for i, pemPath := range pemPaths {
		pemData, err := os.ReadFile(pemPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pem: %s", err.Error())
		}

		fingerprint, err := getCertPemSHA(pemData)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pem: %s", err.Error())
		}
		certFingerprintsToPath[fingerprint] = pemPath
		certFingerprints[i] = fingerprint

		zw, err := zipWriter.Create(fingerprint + ".crt")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("zip: %s", err.Error())
		}
		if _, err := zw.Write(pemData); err != nil {
			return nil, nil, nil, fmt.Errorf("zip: %s", err.Error())
		}
	}
	if err := zipWriter.Close(); err != nil {
		return nil, nil, nil, fmt.Errorf("zip: %s", err.Error())
	}
	zipFile.Close()
	sort.Slice(certFingerprints, func(i, j int) bool {
		return certFingerprints[i] > certFingerprints[j]
	})
	for i, fingerprint := range certFingerprints {
		pemPaths[i] = certFingerprintsToPath[fingerprint]
	}

	args := []string{
		"crl2pkcs7",
		"-nocrl",
	}

	if len(pemPaths) == 0 {
		return nil, nil, nil, fmt.Errorf("no certificates to add to bundle")
	}

	for _, certPath := range pemPaths {
		args = append(args, "-certfile")
		args = append(args, certPath)
	}

	args = append(args, "-out")
	args = append(args, p7bPath)

	os.Remove(p7bPath)
	cmd := exec.Command(opensslPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("openssl error: %s", output)
	}

	os.Remove(pemPath)
	f, err := os.OpenFile(pemPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pem: %s", err.Error())
	}
	defer f.Close()
	for _, pemPath := range pemPaths {
		pemData, err := os.ReadFile(pemPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pem: %s", err.Error())
		}
		f.Write(pemData)
	}

	p7Fingerprints, err := getFileFingerprints(p7bPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("checksum: %s", err.Error())
	}
	pemFingerprints, err := getFileFingerprints(pemPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("checksum: %s", err.Error())
	}
	zipFingerprints, err := getFileFingerprints(zipPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("checksum: %s", err.Error())
	}

	return p7Fingerprints, pemFingerprints, zipFingerprints, nil
}

func writeTemp(data []byte) (string, error) {
	f, err := os.CreateTemp("", "rootca")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	f.Sync()
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
		log.Printf("Bad certificate SHA256. %s %s != %s", certPath, expectedSHA256, actualSHA)
		return false
	}
	return true
}

func getCertPemSHA(certData []byte) (string, error) {
	certPem, _ := pem.Decode(certData)
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return "", err
	}

	signer := sha256.New()
	signer.Write(cert.Raw)
	return fmt.Sprintf("%X", signer.Sum(nil)), nil
}

func convertDerToPem(derPath, pemPath string) (string, error) {
	os.Remove(pemPath)
	derData, err := os.ReadFile(derPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(derData)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derData})
	return fmt.Sprintf("%X", h.Sum(nil)), os.WriteFile(pemPath, pemData, 0644)
}

func getFileFingerprints(filePath string) (*BundleFingerprint, error) {
	d, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	s1 := fmt.Sprintf("%X", sha1.Sum(d))
	s256 := fmt.Sprintf("%X", sha256.Sum256(d))
	s512 := fmt.Sprintf("%X", sha512.Sum512(d))
	return &BundleFingerprint{s1, s256, s512}, nil
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

func checksumCertShaList(thumbprints []string) string {
	bThumbprints := make([][]byte, len(thumbprints))
	for i, thumbprintStr := range thumbprints {
		thumbprint, err := hex.DecodeString(thumbprintStr)
		if err != nil {
			panic("hex: " + err.Error())
		}
		bThumbprints[i] = thumbprint
	}
	sort.Slice(bThumbprints, func(i, j int) bool {
		return bytes.Compare(bThumbprints[i], bThumbprints[j]) >= 1
	})
	h := sha256.New()
	for _, thumbprint := range bThumbprints {
		if _, err := h.Write(thumbprint); err != nil {
			panic("sha: " + err.Error())
		}
	}
	return fmt.Sprintf("%X", h.Sum(nil))
}

// extractP7B will extract the given PKCS#7 bundle and save all certificates in PEM format with the filename
// <SHA-256>.crt
func extractP7B(bundlePath, outputDir string) error {
	output, err := exec.Command(opensslPath, "pkcs7", "-in", bundlePath, "-print_certs").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error extracting certs: %s", err.Error())
	}

	pemCerts := extractPemCerts(output)
	for _, pemCert := range pemCerts {
		sha, err := getCertPemSHA(pemCert)
		if err != nil {
			if strings.Contains(err.Error(), "negative serial number") {
				continue
			}
			return fmt.Errorf("error parsing certificate: %s", err.Error())
		}
		fileName := path.Join(outputDir, sha+".crt")
		os.WriteFile(fileName, pemCert, 0644)
	}
	return nil
}

func isBundleUpToDate(inKey, expectedKey string, bundleName string) bool {
	if inKey != expectedKey {
		return false
	}

	if _, err := os.Stat(bundleName + ".p7b"); err != nil {
		return false
	}
	if _, err := os.Stat(bundleName + ".pem"); err != nil {
		return false
	}

	return true
}
