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
		if lastModified.Before(metadata.MustDate()) {
			logWarning("Apple bundle has modified date '%s' newer than the most recent vendors date '%s'. Skipping update.", metadata.MustDate(), lastModified)
			return metadata, nil
		}
		if isBundleUpToDate(latestSHA, metadata.Key, AppleBundleName) {
			logNotice("Apple bundle is up-to-date")
			return metadata, nil
		}
		logWarning("Detected changes to Apple bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, latestSHA)
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

	logNotice("Apple CA bundle generated with %d certificates", len(certPaths))

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
	type githubTagType struct {
		Name       string `json:"name"`
		TarballURL string `json:"tarball_url"`
		Commit     struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}

	type githubCommitType struct {
		SHA    string `json:"sha"`
		Commit struct {
			Author struct {
				Email string `json:"email"`
				Date  string `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}

	// Get the most recent tag
	tagsResp, err := httpGet("https://api.github.com/repos/apple-oss-distributions/security_certificates/tags")
	if err != nil {
		return "", time.Now(), "", fmt.Errorf("getting tags: %s", err)
	}
	defer tagsResp.Close()

	var tags []githubTagType
	if err := json.NewDecoder(tagsResp).Decode(&tags); err != nil {
		return "", time.Now(), "", err
	}

	// For that tag, get the last commit that touched anything in certificates/roots folder
	// (we don't care about the other contents in this repo)
	commitResp, err := httpGet("https://api.github.com/repos/apple-oss-distributions/security_certificates/commits?path=certificates/roots&sha=" + tags[0].Commit.SHA)
	if err != nil {
		return "", time.Now(), "", fmt.Errorf("getting commit: %s", err)
	}
	defer commitResp.Close()

	commits := []githubCommitType{}
	if err := json.NewDecoder(commitResp).Decode(&commits); err != nil {
		return "", time.Now(), "", err
	}

	if len(commits) == 0 {
		return "", time.Now(), "", fmt.Errorf("no commits found modifying certificates")
	}

	lastCommit := commits[0]

	if lastCommit.Commit.Author.Email != "91980991+AppleOSSDistributions@users.noreply.github.com" {
		return "", time.Now(), "", fmt.Errorf("safety cut-out: unrecognized commit author: %s", lastCommit.Commit.Author.Email)
	}

	date, err := time.Parse("2006-01-02T15:04:05Z", lastCommit.Commit.Author.Date)
	if err != nil {
		date = time.Now()
	}

	return lastCommit.SHA, date, tags[0].TarballURL, nil
}
