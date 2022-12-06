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

	if metadata != nil && metadata.SHA256 == currentSHA {
		log.Printf("Microsoft bundle is up-to-date")
		return metadata, nil
	}

	r := csv.NewReader(strings.NewReader(caCSV))

	thumbprints := [][]string{}

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

		thumbprints = append(thumbprints, []string{certSHA1, certSHA256})
	}

	os.Mkdir("microsoft_certs", 7644)
	certPaths := make([]string, len(thumbprints))
	for i, tp := range thumbprints {
		certSHA1 := tp[0]
		certSHA256 := tp[1]
		certPath := path.Join("microsoft_certs", certSHA1+".crt")

		if _, err := os.Stat(certPath); err == nil {
			if !verifyCertDerSHA(certPath, certSHA256) {
				log.Printf("Cached Microsoft certificate %s.crt is bad", certSHA1)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths[i] = certPath
				continue
			}
		}

		if err := downloadFile(fmt.Sprintf("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/%s.crt", certSHA1), certPath); err != nil {
			return nil, err
		}
		certPaths[i] = certPath
		log.Printf("Downloaded %s.crt", certSHA1)
	}

	if err := makeP7BFromCerts(certPaths, MicrosoftBundleName); err != nil {
		return nil, err
	}

	return &VendorMetadata{
		Date:     time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		SHA256:   currentSHA,
		NumCerts: len(certPaths),
	}, nil
}

func getMicrosoftSHA(csvData string) string {
	dgst := sha256.New()
	dgst.Write([]byte(csvData))
	return fmt.Sprintf("%X", dgst.Sum(nil))
}
