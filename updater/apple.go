package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const AppleBundleName = "apple_ca_bundle"

func buildAppleBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	latestSHA, lastModified, tarballURL, err := getLatestAppleSHA()
	if err != nil {
		return nil, err
	}

	if metadata != nil && !forceUpdate {
		if isBundleUpToDate(latestSHA, metadata.Key, AppleBundleName) {
			log.Printf("Apple bundle is up-to-date")
			return metadata, nil
		}
		log.Printf("Detected changes to Apple bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, latestSHA)
	}
	log.Printf("Building Apple CA bundle")

	tempDir, err := os.MkdirTemp("", "apple")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	tarballPath := path.Join(tempDir, "apple.tar.gz")
	if err := downloadFile(tarballURL, tarballPath); err != nil {
		return nil, fmt.Errorf("error downloading archive: %s", err.Error())
	}

	exCmd := exec.Command("tar", "-xzf", tarballPath, "--strip", "1")
	exCmd.Dir = tempDir
	if err := exCmd.Run(); err != nil {
		return nil, fmt.Errorf("error extracting archive: %s", err.Error())
	}

	outputDir := path.Join(tempDir, "bundle")
	os.Mkdir(outputDir, os.ModePerm)
	certificateDir := path.Join(tempDir, "certificates", "roots")
	items, err := os.ReadDir(certificateDir)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate directory: %s", err.Error())
	}
	certPaths := []string{}
	for i, item := range items {
		if !strings.HasSuffix(item.Name(), ".cer") && !strings.HasSuffix(item.Name(), ".der") && !strings.HasSuffix(item.Name(), ".crt") {
			continue
		}
		certPath := path.Join(outputDir, fmt.Sprintf("cert_%d.crt", i))
		_, err := convertDerToPem(path.Join(certificateDir, item.Name()), certPath)
		if err != nil {
			return nil, fmt.Errorf("error converting certificate: %s", err.Error())
		}
		certPaths = append(certPaths, certPath)
	}

	p7Fingerprints, pemFingerprints, err := generateBundleFromCertificates(certPaths, AppleBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Apple CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key: latestSHA,
		Bundles: map[string]BundleFingerprint{
			AppleBundleName + ".p7b": *p7Fingerprints,
			AppleBundleName + ".pem": *pemFingerprints,
		},
		Date:     lastModified.Format("2006-01-02T15:04:05Z07:00"),
		NumCerts: len(certPaths),
	}, nil
}

func getLatestAppleSHA() (string, time.Time, string, error) {
	resp, err := httpGetString("https://api.github.com/repos/apple-oss-distributions/security_certificates/tags")
	if err != nil {
		return "", time.Now(), "", err
	}

	type tagType struct {
		Name       string `json:"name"`
		TarballURL string `json:"tarball_url"`
		Commit     struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	var tags []tagType
	if err := json.Unmarshal([]byte(resp), &tags); err != nil {
		return "", time.Now(), "", err
	}

	resp, err = httpGetString("https://api.github.com/repos/apple-oss-distributions/security_certificates/commits?sha=" + tags[0].Commit.SHA)
	if err != nil {
		return "", time.Now(), "", err
	}

	ghResponse := []map[string]interface{}{}
	if err := json.Unmarshal([]byte(resp), &ghResponse); err != nil {
		return "", time.Now(), "", err
	}

	if len(ghResponse) < 1 {
		return "", time.Now(), "", fmt.Errorf("no commit")
	}

	sha := ghResponse[0]["sha"].(string)
	dateStr := ghResponse[0]["commit"].(map[string]interface{})["author"].(map[string]interface{})["date"].(string)
	date, err := time.Parse("2006-01-02T15:04:05Z", dateStr)
	if err != nil {
		date = time.Now()
	}

	return sha, date, tags[0].TarballURL, nil
}
