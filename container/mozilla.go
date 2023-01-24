package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const MozillaBundleName = "mozilla_ca_bundle"

func buildMozillaBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	latestSHA, err := getMozillaSHA()
	if err != nil {
		return nil, err
	}

	if metadata != nil && !forceUpdate {
		if isBundleUpToDate(latestSHA, metadata.Key, MozillaBundleName) {
			log.Printf("Mozilla bundle is up-to-date")
			return metadata, nil
		}
		log.Printf("Detected changes to Mozilla bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, latestSHA)
	}
	log.Printf("Building Mozilla CA bundle")

	pemData, err := httpGetBytes("https://curl.se/ca/cacert.pem")
	if err != nil {
		return nil, err
	}

	pemCerts := extractPemCerts(pemData)

	if len(pemCerts) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	datePatterm := regexp.MustCompile(`## Certificate data from Mozilla as of: [A-Za-z0-9 :]+`)
	dateStr := string(datePatterm.Find(pemData))
	dateStr = strings.ReplaceAll(dateStr, "## Certificate data from Mozilla as of: ", "")

	tempDir, err := os.MkdirTemp("", "mozilla")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	certPaths := make([]string, len(pemCerts))
	for i := 0; i < len(pemCerts); i++ {
		certPaths[i] = path.Join(tempDir, fmt.Sprintf("cert_%d.crt", i))
		if err := os.WriteFile(certPaths[i], pemCerts[i], 0644); err != nil {
			return nil, err
		}
	}

	date, err := time.Parse("Mon Jan 02 15:04:05 2006 MST", dateStr)
	if err != nil {
		date = time.Now().UTC()
	}

	p7Fingerprints, pemFingerprints, err := generateBundleFromCertificates(certPaths, MozillaBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Mozilla CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key: latestSHA,
		Bundles: map[string]BundleFingerprint{
			MozillaBundleName + ".p7b": *p7Fingerprints,
			MozillaBundleName + ".pem": *pemFingerprints,
		},
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
