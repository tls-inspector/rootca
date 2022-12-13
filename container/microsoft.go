package main

import (
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
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

	thumbprints := [][]string{}
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

		thumbprints = append(thumbprints, []string{strings.ToUpper(certSHA1), strings.ToUpper(certSHA256)})
		thumbprintMap[strings.ToUpper(certSHA1)] = true
	}

	os.Mkdir("microsoft_certs", 7644)
	certPaths := make([]string, len(thumbprints))
	for i, tp := range thumbprints {
		certSHA1 := tp[0]
		certSHA256 := tp[1]
		certPath := path.Join("microsoft_certs", certSHA1+".crt")

		if _, err := os.Stat(certPath); err == nil {
			if !verifyCertPEMSHA(certPath, certSHA256) {
				log.Printf("Cached Microsoft certificate %s.crt is bad", certSHA1)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths[i] = certPath
				continue
			}
		}

		derCertPath := path.Join("microsoft_certs", certSHA1+".bin")

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

	certFiles, err := os.ReadDir("microsoft_certs")
	if err != nil {
		return nil, err
	}
	for _, certFile := range certFiles {
		sha := strings.ToUpper(certFile.Name())
		sha = sha[0 : len(sha)-4]

		if !thumbprintMap[sha] {
			os.Remove(path.Join("microsoft_certs", certFile.Name()))
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

func getMicrosoftSHA(csvData string) string {
	dgst := sha256.New()
	dgst.Write([]byte(csvData))
	return fmt.Sprintf("%X", dgst.Sum(nil))
}
