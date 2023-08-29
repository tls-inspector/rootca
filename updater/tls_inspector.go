package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

const TLSInspectorBundleName = "tlsinspector_ca_bundle"

func buildTLSInspectorBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	const (
		t_apple = 1 << iota
		t_google
		t_microsoft
		t_mozilla
	)

	appleDir, err := os.MkdirTemp("", "apple")
	if err != nil {
		return nil, err
	}
	if err := extractP7B(AppleBundleName+".p7b", appleDir); err != nil {
		return nil, err
	}
	defer os.RemoveAll(appleDir)
	appleCerts, err := scanDirectoryForCertificates(appleDir)
	if err != nil {
		return nil, err
	}

	googleDir, err := os.MkdirTemp("", "google")
	if err != nil {
		return nil, err
	}
	if err := extractP7B(GoogleBundleName+".p7b", googleDir); err != nil {
		return nil, err
	}
	defer os.RemoveAll(googleDir)
	googleCerts, err := scanDirectoryForCertificates(googleDir)
	if err != nil {
		return nil, err
	}

	microsoftDir, err := os.MkdirTemp("", "microsoft")
	if err != nil {
		return nil, err
	}
	if err := extractP7B(MicrosoftBundleName+".p7b", microsoftDir); err != nil {
		return nil, err
	}
	defer os.RemoveAll(microsoftDir)
	microsoftCerts, err := scanDirectoryForCertificates(microsoftDir)
	if err != nil {
		return nil, err
	}

	mozillaDir, err := os.MkdirTemp("", "mozilla")
	if err != nil {
		return nil, err
	}
	if err := extractP7B(MozillaBundleName+".p7b", mozillaDir); err != nil {
		return nil, err
	}
	defer os.RemoveAll(mozillaDir)
	mozillaCerts, err := scanDirectoryForCertificates(mozillaDir)
	if err != nil {
		return nil, err
	}

	certKeyToShaMap := map[string]string{}
	certBundlePresenceMap := map[string]int{}
	for _, cert := range appleCerts {
		keyId := fmt.Sprintf("%X", cert.SubjectKeyId)
		certKeyToShaMap[keyId] = fmt.Sprintf("%X", sha256.Sum256(cert.Raw))
		certBundlePresenceMap[keyId] |= t_apple
	}
	for _, cert := range googleCerts {
		keyId := fmt.Sprintf("%X", cert.SubjectKeyId)
		certBundlePresenceMap[keyId] |= t_google
	}
	for _, cert := range microsoftCerts {
		keyId := fmt.Sprintf("%X", cert.SubjectKeyId)
		certBundlePresenceMap[keyId] |= t_microsoft
	}
	for _, cert := range mozillaCerts {
		keyId := fmt.Sprintf("%X", cert.SubjectKeyId)
		certBundlePresenceMap[keyId] |= t_mozilla
	}

	certPaths := []string{}
	shas := []string{}
	for keyId, presence := range certBundlePresenceMap {
		if presence != 15 {
			continue
		}
		sha := certKeyToShaMap[keyId]

		shas = append(shas, sha)
		certPaths = append(certPaths, path.Join(appleDir, sha+".crt"))
	}

	currentSHA := checksumCertShaList(shas)
	if metadata != nil && !forceUpdate {
		if isBundleUpToDate(currentSHA, metadata.Key, TLSInspectorBundleName) {
			logNotice("TLSInspector bundle is up-to-date")
			return metadata, nil
		}
		logWarning("Detected changes to TLSInspector bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, currentSHA)
	}
	log.Printf("Building TLSInspector CA bundle")

	p7Fingerprints, pemFingerprints, err := generateBundleFromCertificates(certPaths, TLSInspectorBundleName)
	if err != nil {
		return nil, err
	}

	logNotice("TLSInspector CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Date: time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		Key:  currentSHA,
		Bundles: map[string]BundleFingerprint{
			TLSInspectorBundleName + ".p7b": *p7Fingerprints,
			TLSInspectorBundleName + ".pem": *pemFingerprints,
		},
		NumCerts: len(certPaths),
	}, nil
}

func scanDirectoryForCertificates(dirName string) ([]x509.Certificate, error) {
	files, err := os.ReadDir(dirName)
	if err != nil {
		return nil, err
	}
	certificates := []x509.Certificate{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".crt") {
			continue
		}

		data, err := os.ReadFile(path.Join(dirName, file.Name()))
		if err != nil {
			return nil, err
		}

		certPem, _ := pem.Decode(data)
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, *cert)
	}
	return certificates, nil
}
