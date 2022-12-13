package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

const MozillaBundleName = "mozilla_ca_bundle.p7b"

func buildMozillaBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	latestSHA, err := getMozillaSHA()
	if err != nil {
		return nil, err
	}

	if metadata != nil && metadata.SHA256 == latestSHA {
		log.Printf("Mozilla bundle is up-to-date")
		return metadata, nil
	}
	log.Printf("Building Mozilla CA bundle")

	pemData, err := httpGetString("https://curl.se/ca/cacert.pem")
	if err != nil {
		return nil, err
	}

	pemCerts := []string{}
	pem := ""
	isInCert := false
	dateStr := ""

	scanner := bufio.NewScanner(strings.NewReader(pemData))
	for scanner.Scan() {
		line := scanner.Text()

		if line == "-----BEGIN CERTIFICATE-----" {
			isInCert = true
		}

		if isInCert {
			pem += line + "\n"

			if line == "-----END CERTIFICATE-----" {
				pemCerts = append(pemCerts, pem)
				pem = ""
				isInCert = false
			}
		} else if strings.Contains(line, "## Certificate data from Mozilla as of:") {
			dateStr = strings.ReplaceAll(line, "## Certificate data from Mozilla as of: ", "")
		}
	}

	if len(pemCerts) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	tempDir, err := os.MkdirTemp("", "mozilla")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	certPaths := make([]string, len(pemCerts))
	for i := 0; i < len(pemCerts); i++ {
		certPaths[i] = path.Join(tempDir, fmt.Sprintf("cert_%d.crt", i))
		if err := os.WriteFile(certPaths[i], []byte(pemCerts[i]), 0644); err != nil {
			return nil, err
		}
	}

	date, err := time.Parse("Mon Jan 02 15:04:05 2006 MST", dateStr)
	if err != nil {
		date = time.Now().UTC()
	}

	if err := makeP7BFromCerts(certPaths, MozillaBundleName); err != nil {
		return nil, err
	}

	hash, err := shaSumFile(MozillaBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Mozilla CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key:      latestSHA,
		SHA256:   hash,
		Date:     date.Format("2006-01-02T15:04:05Z07:00"),
		NumCerts: len(pemCerts),
	}, nil
}

func getMozillaSHA() (string, error) {
	resp, err := httpGetString("https://curl.se/ca/cacert.pem.sha256")
	if err != nil {
		return "", nil
	}

	return strings.Split(resp, " ")[0], nil
}
