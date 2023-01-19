package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"time"
)

const GoogleBundleName = "google_ca_bundle"

func buildGoogleBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	latestSHA, lastModified, err := getLatestGoogleSHA()
	if err != nil {
		return nil, err
	}

	if metadata != nil {
		if isBundleUpToDate(latestSHA, metadata.Key, GoogleBundleName) {
			log.Printf("Google bundle is up-to-date")
			return metadata, nil
		}
		log.Printf("Detected changes to Google bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, latestSHA)
	}
	log.Printf("Building Google CA bundle")

	pemData, err := httpGetBytes("https://raw.githubusercontent.com/chromium/chromium/main/net/data/ssl/chrome_root_store/root_store.certs")
	if err != nil {
		return nil, err
	}

	pemCerts := extractPemCerts(pemData)

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

	p7Fingerprints, pemFingerprints, err := generateBundleFromCertificates(certPaths, GoogleBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Google CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key: latestSHA,
		Bundles: map[string]BundleFingerprint{
			GoogleBundleName + ".p7b": *p7Fingerprints,
			GoogleBundleName + ".pem": *pemFingerprints,
		},
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
