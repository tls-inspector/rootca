package main

import (
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const MicrosoftBundleName = "microsoft_ca_bundle.p7b"

func buildMicrosoftBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	caCSV, err := httpGetString("https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV")
	if err != nil {
		return nil, err
	}

	currentSHA := getMicrosoftSHA(caCSV)

	if metadata != nil && metadata.Key == currentSHA {
		log.Printf("Microsoft bundle is up-to-date")
		return metadata, nil
	}
	log.Printf("Building Microsoft CA bundle")

	r := csv.NewReader(strings.NewReader(caCSV))

	type thumbprintType struct {
		SHA1   string
		SHA256 string
	}
	thumbprints := []thumbprintType{}
	thumbprintMap := map[string]bool{}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		status := record[0]
		certSHA1 := record[3]
		certSHA256 := record[4]
		msEKU := record[5]
		notAfterStr := record[7]

		if status == "Disabled" {
			continue // Skip disabled certificates
		}

		// 2025 Jul 23
		notAfter, err := time.Parse("2006 Jan 02", notAfterStr)
		if err != nil {
			continue
		}

		if time.Now().UTC().After(notAfter) {
			continue // Skip expired certificates
		}

		if !strings.Contains(msEKU, "Server Authentication") {
			// Skip certificates that Microsoft has not marked as being suitable for server authentication
			// (note that these EKUs don't appear on the certificate itself)
			continue
		}

		thumbprints = append(thumbprints, thumbprintType{strings.ToUpper(certSHA1), strings.ToUpper(certSHA256)})
		thumbprintMap[strings.ToUpper(certSHA256)] = true
	}

	tmpDir, err := os.MkdirTemp("", "microsoft")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	if fileExists(MicrosoftBundleName) {
		if err := extractMicrosoftCerts(tmpDir); err != nil {
			return nil, fmt.Errorf("error extracting microsoft certificates: %s", err.Error())
		}
	}

	certPaths := make([]string, len(thumbprints))
	for i, tp := range thumbprints {
		certSHA1 := tp.SHA1
		certSHA256 := tp.SHA256
		certPath := path.Join(tmpDir, certSHA256+".crt")

		if fileExists(certPath) {
			if !verifyCertPEMSHA(certPath, certSHA256) {
				log.Printf("Cached Microsoft certificate %s.crt is bad", certSHA1)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths[i] = certPath
				continue
			}
		}

		derCertPath := path.Join(tmpDir, certSHA1+".bin")

		if err := downloadFile(fmt.Sprintf("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/%s.crt", certSHA1), derCertPath); err != nil {
			return nil, err
		}
		if err := convertDerToPem(derCertPath, certPath); err != nil {
			return nil, err
		}
		os.Remove(derCertPath)
		log.Printf("Downloaded and converted %s.crt", certSHA1)
		certPaths[i] = certPath
	}

	certFiles, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, err
	}
	for _, certFile := range certFiles {
		sha := strings.ToUpper(certFile.Name())
		sha = sha[0 : len(sha)-4]

		if !thumbprintMap[sha] {
			os.Remove(path.Join(tmpDir, certFile.Name()))
			log.Printf("Removed unused Microsoft certificate %s", certFile.Name())
		}
	}

	os.Remove(MicrosoftBundleName)
	if err := makeP7BFromCerts(certPaths, MicrosoftBundleName); err != nil {
		return nil, err
	}

	hash, err := shaSumFile(MicrosoftBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Microsoft CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Date:     time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		Key:      currentSHA,
		SHA256:   hash,
		NumCerts: len(certPaths),
	}, nil
}

func extractMicrosoftCerts(outputDir string) error {
	output, err := exec.Command("openssl", "pkcs7", "-in", MicrosoftBundleName, "-print_certs").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error extracting certs: %s", err.Error())
	}

	pemCerts := extractPemCerts(output)
	for _, pemCert := range pemCerts {
		sha, err := getCertPemSHA(pemCert)
		if err != nil {
			return fmt.Errorf("error parsing certificate: %s", err.Error())
		}
		fileName := path.Join(outputDir, sha+".crt")
		os.WriteFile(fileName, pemCert, 0644)
	}
	return nil
}

func getMicrosoftSHA(csvData string) string {
	dgst := sha256.New()
	dgst.Write([]byte(csvData))
	return fmt.Sprintf("%X", dgst.Sum(nil))
}
