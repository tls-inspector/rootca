package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/tlsinspector/rootca/apple"
)

const AppleBundleName = "apple_ca_bundle"

type appleAnchorType map[string][]appleAnchorEntry

type appleAnchorEntry struct {
	SpkiSha2   string   `json:"spki-sha2"`
	AnchorType string   `json:"type"`
	OIDs       []string `json:"oids"`
	SHA2       string   `json:"sha2"`
}

const appleTLSServerOID = "1.2.840.113635.100.1.3.1"

type appleAssetJwtPayload struct {
	Assets []appleAsset
}

type appleAsset struct {
	ArchiveDecryptionKey string
	ContentVersion       uint64
	BaseURL              string `json:"__BaseURL"`
	RelativePath         string `json:"__RelativePath"`
}

func buildAppleBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	if runtime.GOOS != "darwin" {
		log.Printf("WARNING: Updating the Apple bundle can only be done on a macOS device. This is a known limitation that we're trying to fix, but have no timeline to provide.")
		return metadata, nil
	}

	asset, err := getAppleAssetMetadata()
	if err != nil {
		return nil, err
	}
	contentVersion := fmt.Sprintf("%d", asset.ContentVersion)
	lastModified, err := time.Parse("20060102", contentVersion[0:8])

	if metadata != nil && !forceUpdate {
		if isBundleUpToDate(contentVersion, metadata.Key, AppleBundleName) {
			logNotice("Apple bundle is up-to-date")
			return metadata, nil
		}
		logWarning("Detected changes to Apple bundle. LastVersion='%s' LatestVersion='%s'", metadata.Key, contentVersion)
	}
	log.Printf("Building Apple CA bundle")

	tempDir, err := os.MkdirTemp("", "apple")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	outputDir := path.Join(tempDir, "bundle")
	if err := os.Mkdir(outputDir, os.ModePerm); err != nil {
		return nil, err
	}

	resp, err := httpGet(asset.BaseURL + asset.RelativePath)
	if err != nil {
		return nil, err
	}

	certPaths := []string{}

	err = apple.Mount(resp, asset.ArchiveDecryptionKey, func(mountPoint string) error {
		anchorsPath := path.Join(tempDir, "anchors.json")
		if err := apple.ConvertPlist(path.Join(mountPoint, "Anchors.plist"), anchorsPath); err != nil {
			return err
		}

		var anchors appleAnchorType
		r, err := os.Open(anchorsPath)
		if err != nil {
			return err
		}
		if err := json.NewDecoder(r).Decode(&anchors); err != nil {
			return err
		}

		var selectedCertificates = []string{}

		for _, entries := range anchors {
			if len(entries) == 0 {
				continue
			}

			// Valid anchors must match all:
			// 1. Have a type of "system"
			// 2. Either of:
			//   2.1. Have TLS server usage
			//   2.2. Have unrestricted usage (no OIDs)

			validIndex := -1
			for i, entry := range entries {
				hasSystemType := entry.AnchorType == "system"
				usageIsUnrestricted := len(entry.OIDs) == 0
				usageAllowsTLSServer := slices.Contains(entry.OIDs, appleTLSServerOID)

				if hasSystemType && (usageIsUnrestricted || usageAllowsTLSServer) {
					validIndex = i
					break
				}
			}
			if validIndex >= 0 {
				selectedCertificates = append(selectedCertificates, entries[validIndex].SHA2)
			}
		}

		if len(selectedCertificates) == 0 {
			return fmt.Errorf("unable to locate anchor certificates from apple bundle")
		}

		for i, sha2 := range selectedCertificates {
			derPath := path.Join(mountPoint, "Anchors", sha2+".cer")
			pemPath := path.Join(outputDir, fmt.Sprintf("cert_%d.crt", i))
			hash, err := convertDerToPem(derPath, pemPath)
			if err != nil {
				return fmt.Errorf("error converting certificate from der to pem: %s %s", derPath, err.Error())
			}
			if !strings.EqualFold(hash, sha2) {
				return fmt.Errorf("actual certificate data does not match anchor file? %s != %s", hash, sha2)
			}

			certPaths = append(certPaths, pemPath)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	p7Fingerprints, pemFingerprints, zipFingerprints, err := generateBundleFromCertificates(certPaths, AppleBundleName)
	if err != nil {
		return nil, err
	}

	logNotice("Apple CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Key: contentVersion,
		Bundles: map[string]BundleFingerprint{
			AppleBundleName + ".p7b": *p7Fingerprints,
			AppleBundleName + ".pem": *pemFingerprints,
			AppleBundleName + ".zip": *zipFingerprints,
		},
		Date:     lastModified.Format("2006-01-02T15:04:05Z07:00"),
		NumCerts: len(certPaths),
	}, nil
}

func getAppleAssetMetadata() (*appleAsset, error) {
	req, err := http.NewRequest("POST", "https://gdmf.apple.com/v2/assets", bytes.NewBufferString(`{"ClientVersion": 2,"AssetAudience": "02d8e57e-dd1c-4090-aa50-b4ed2aef0062","AssetType": "com.apple.MobileAsset.PKITrustStore"}`))
	if err != nil {
		return nil, fmt.Errorf("getting asset jwt: %s", err.Error())
	}
	req.Header.Set("User-Agent", httpRequestUserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting asset jwt: %s", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getting asset jwt: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		log.Printf("HTTP error from Apple: %s", body)
		return nil, fmt.Errorf("getting asset jwt: HTTP %d", resp.StatusCode)
	}

	// Response is a JWT, but verifying it is largely uneccessary since its sent over HTTPS
	jwtParts := bytes.Split(body, []byte("."))
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("getting asset jwt: invalid jwt response")
	}

	jwtPayloadData, err := base64.StdEncoding.DecodeString(string(jwtParts[1]))
	if err != nil {
		return nil, fmt.Errorf("getting asset jwt: %s", err.Error())
	}

	var jwtPayload appleAssetJwtPayload
	if err := json.Unmarshal(jwtPayloadData, &jwtPayload); err != nil {
		return nil, fmt.Errorf("getting asset jwt: %s", err.Error())
	}

	if len(jwtPayload.Assets) == 0 {
		return nil, fmt.Errorf("getting asset jwt: no assets")
	}

	asset := jwtPayload.Assets[0]
	return &asset, nil
}
