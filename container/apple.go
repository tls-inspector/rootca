package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const AppleBundleName = "apple_ca_bundle.p7b"

func buildAppleBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	thumbprints, err := getAppleCertThumbprints()
	if err != nil {
		return nil, err
	}
	currentSHA := checksumCertShaList(thumbprints)
	thumbprintMap := map[string]bool{}
	for _, thumbprint := range thumbprints {
		thumbprintMap[thumbprint] = true
	}

	if metadata != nil {
		if metadata.Key == currentSHA {
			log.Printf("Apple bundle is up-to-date")
			return metadata, nil
		}
		log.Printf("Detected changes to Apple bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, currentSHA)
	}
	log.Printf("Building Apple CA bundle")

	tmpDir, err := os.MkdirTemp("", "apple")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	if fileExists(AppleBundleName) {
		if err := extractP7B(AppleBundleName, tmpDir); err != nil {
			return nil, fmt.Errorf("error extracting apple certificates: %s", err.Error())
		}
	}

	certPaths := make([]string, len(thumbprints))
	for i, thumbprint := range thumbprints {
		certPath := path.Join(tmpDir, thumbprint+".crt")

		if fileExists(certPath) {
			if !verifyCertPEMSHA(certPath, thumbprint) {
				log.Printf("Cached Apple certificate %s.crt is bad", thumbprint)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths[i] = certPath
				continue
			}
		}

		if err := downloadFile("https://crt.sh/?d="+thumbprint, certPath); err != nil {
			return nil, err
		}
		if !verifyCertPEMSHA(certPath, thumbprint) {
			return nil, fmt.Errorf("downloaded certificate verification failed")
		}
		log.Printf("Downloaded new certificate for Apple bundle %s", thumbprint)
		certPaths[i] = certPath
		time.Sleep(1500 * time.Millisecond)
	}

	certFiles, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, err
	}
	for _, certFile := range certFiles {
		sha := strings.ToUpper(certFile.Name())
		if len(sha) != 68 {
			continue
		}
		sha = sha[0 : len(sha)-4]

		if !thumbprintMap[sha] {
			os.Remove(path.Join(tmpDir, certFile.Name()))
			log.Printf("Removed unused Apple certificate %s", certFile.Name())
		}
	}

	os.Remove(AppleBundleName)
	if err := makeP7BFromCerts(certPaths, AppleBundleName); err != nil {
		return nil, err
	}

	hash, err := shaSumFile(AppleBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Apple CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Date:     time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		Key:      currentSHA,
		SHA256:   hash,
		NumCerts: len(certPaths),
	}, nil
}

func getAppleCertThumbprints() ([]string, error) {
	thumbprints := []string{}

	resp, err := httpGet("https://support.apple.com/en-ca/HT213464")
	if err != nil {
		return nil, err
	}

	doc, err := html.Parse(resp)
	if err != nil {
		return nil, err
	}
	inTable := false
	tdCount := 0
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "table" {
			if inTable {
				return
			}
			inTable = true
		}
		if inTable && n.Type == html.ElementNode && n.Data == "tr" {
			tdCount = 0
		}
		if inTable && n.Type == html.ElementNode && n.Data == "td" {
			tdCount++
			if tdCount == 9 {
				sha256 := strings.ReplaceAll(n.FirstChild.Data, " ", "")
				sha256 = strings.ReplaceAll(sha256, "\u00a0", "")

				if sha256 == "41A235AB60F0643E752A2DB4E914D68C0542167DE9CA28DF25FD79A693C29072" {
					panic("apple: safety check failure")
				}

				thumbprints = append(thumbprints, strings.ToUpper(sha256))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return thumbprints, nil
}
