package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

const GoogleBundleName = "google_ca_bundle.p7b"

func buildGoogleBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	latestSHA, lastModified, err := getLatestGoogleSHA()
	if err != nil {
		return nil, err
	}

	if metadata != nil && metadata.Key == latestSHA {
		log.Printf("Google bundle is up-to-date")
		return metadata, nil
	}
	log.Printf("Building Google CA bundle")

	pemData, err := httpGetString("https://raw.githubusercontent.com/chromium/chromium/main/net/data/ssl/chrome_root_store/root_store.certs")
	if err != nil {
		return nil, err
	}

	pemCerts := []string{}
	pem := ""
	isInCert := false

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
		}
	}

	if len(pemCerts) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	tempDir, err := os.MkdirTemp("", "google")
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

	if err := makeP7BFromCerts(certPaths, GoogleBundleName); err != nil {
		return nil, err
	}

	hash, err := shaSumFile(GoogleBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Google CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key:      latestSHA,
		SHA256:   hash,
		Date:     lastModified.Format("2006-01-02T15:04:05Z07:00"),
		NumCerts: len(pemCerts),
	}, nil
}

func getLatestGoogleSHA() (string, time.Time, error) {
	resp, err := httpGetString("https://api.github.com/repos/chromium/chromium/commits?path=net/data/ssl/chrome_root_store/root_store.certs")
	if err != nil {
		return "", time.Now(), err
	}

	ghResponse := []map[string]interface{}{}
	if err := json.Unmarshal([]byte(resp), &ghResponse); err != nil {
		return "", time.Now(), err
	}

	if len(ghResponse) < 1 {
		return "", time.Now(), fmt.Errorf("no commit")
	}

	sha := ghResponse[0]["sha"].(string)
	dateStr := ghResponse[0]["commit"].(map[string]interface{})["author"].(map[string]interface{})["date"].(string)
	date, err := time.Parse("2006-01-02T15:04:05Z", dateStr)
	if err != nil {
		date = time.Now()
	}

	return sha, date, nil
}
