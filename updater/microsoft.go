package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/tls-inspector/authrootstl"
)

type microsoftBundleCacheType struct {
	ExcludeCertificates []string `json:"excluded_certificates"`
}

const MicrosoftBundleName = "microsoft_ca_bundle"
const microsoftBundleCacheName = ".microsoft_cache.json"

func buildMicrosoftBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	bundleCache := loadMicrosoftBundleCache()
	subjects, currentSHA, err := getMicrosoftSubjects()
	if err != nil {
		return nil, fmt.Errorf("unable to get microsoft suvjects: %s", err.Error())
	}
	if metadata != nil && !forceUpdate {
		if isBundleUpToDate(currentSHA, metadata.Key, MicrosoftBundleName) {
			logNotice("Microsoft bundle is up-to-date")
			return metadata, nil
		}
		logWarning("Detected changes to Microsoft bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, currentSHA)
	}
	log.Printf("Building Microsoft CA bundle")

	tmpDir, err := os.MkdirTemp("", "microsoft")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	if fileExists(MicrosoftBundleName + ".p7b") {
		if err := extractP7B(MicrosoftBundleName+".p7b", tmpDir); err != nil {
			return nil, fmt.Errorf("error extracting microsoft certificates: %s", err.Error())
		}
	}

	thumbprintMap := map[string]bool{}

	certPaths := []string{}
	for _, subject := range subjects {
		if subject.DisabledDate != nil {
			continue
		}
		if subject.MicrosoftExtendedKeyUsage&authrootstl.KeyUsageServerAuthentication == 0 {
			continue
		}
		if sliceContains(bundleCache.ExcludeCertificates, subject.SHA256Fingerprint) {
			continue
		}
		thumbprintMap[subject.SHA256Fingerprint] = true

		certPath := path.Join(tmpDir, subject.SHA256Fingerprint+".crt")

		if fileExists(certPath) {
			if !verifyCertPEMSHA(certPath, subject.SHA256Fingerprint) {
				log.Printf("Cached Microsoft certificate %s.crt is bad", subject.SHA1Fingerprint)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths = append(certPaths, certPath)
				continue
			}
		}

		derCertPath := path.Join(tmpDir, subject.SHA1Fingerprint+".bin")

		if err := downloadFile(fmt.Sprintf("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/%s.crt", subject.SHA1Fingerprint), derCertPath); err != nil {
			return nil, err
		}
		isExpired, err := microsoftCertificateIsExpired(derCertPath)
		if err != nil {
			return nil, err
		}
		if isExpired {
			bundleCache.ExcludeCertificates = append(bundleCache.ExcludeCertificates, subject.SHA256Fingerprint)
			log.Printf("Skipping expired or soon-to-expire certificate %s", subject.SHA256Fingerprint)
			thumbprintMap[subject.SHA256Fingerprint] = false
			continue
		}

		dlThumbprint, err := convertDerToPem(derCertPath, certPath)
		if err != nil {
			return nil, err
		}
		if dlThumbprint != subject.SHA256Fingerprint {
			return nil, fmt.Errorf("downloaded certificate verification failed")
		}

		os.Remove(derCertPath)
		log.Printf("Downloaded and converted %s.crt", subject.SHA1Fingerprint)
		certPaths = append(certPaths, certPath)
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
			log.Printf("Removed unused Microsoft certificate %s", certFile.Name())
		}
	}

	p7Fingerprints, pemFingerprints, err := generateBundleFromCertificates(certPaths, MicrosoftBundleName)
	if err != nil {
		return nil, err
	}

	saveMicrosoftBundleCache(&bundleCache)
	logNotice("Microsoft CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Date: time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		Key:  currentSHA,
		Bundles: map[string]BundleFingerprint{
			MicrosoftBundleName + ".p7b": *p7Fingerprints,
			MicrosoftBundleName + ".pem": *pemFingerprints,
		},
		NumCerts: len(certPaths),
	}, nil
}

func getMicrosoftSubjects() ([]authrootstl.Subject, string, error) {
	dlDir, err := os.MkdirTemp("", "authrootstl")
	if err != nil {
		return nil, "", fmt.Errorf("error making download directory for authrootstl: %s", err.Error())
	}
	defer os.RemoveAll(dlDir)

	cabPath := path.Join(dlDir, "authrootstl.cab")
	stlPath := path.Join(dlDir, "authroot.stl")
	if err := downloadFile("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab", cabPath); err != nil {
		return nil, "", fmt.Errorf("error downloading authrootstl.cab: %s", err.Error())
	}
	if err := exec.Command(cabextractPath, "-d", dlDir, cabPath).Run(); err != nil {
		return nil, "", fmt.Errorf("eror extracting authrootstl.cab: %s", err.Error())
	}
	if _, err := os.Stat(stlPath); err != nil {
		return nil, "", fmt.Errorf("authroot.stl does not exist or not accessable: %s", err.Error())
	}

	data, err := os.ReadFile(stlPath)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read authroot.stl: %s", err.Error())
	}
	hash := fmt.Sprintf("%X", sha256.Sum256(data))
	subjects, err := authrootstl.Parse(data)
	if err != nil {
		return nil, "", err
	}
	return subjects, hash, nil
}

func microsoftCertificateIsExpired(derCertPath string) (bool, error) {
	data, err := os.ReadFile(derCertPath)
	if err != nil {
		return false, err
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return false, err
	}
	return time.Since(cert.NotAfter) > -7*(24*time.Hour), nil // cert expires within 7 days or already expired
}

func loadMicrosoftBundleCache() microsoftBundleCacheType {
	bundleCache := microsoftBundleCacheType{}
	if _, err := os.Stat(microsoftBundleCacheName); err == nil {
		f, err := os.Open(microsoftBundleCacheName)
		if err != nil {
			log.Printf("Error reading microsoft bundle cache (ignoring error): %s", err.Error())
			return bundleCache
		}
		err = json.NewDecoder(f).Decode(&bundleCache)
		f.Close()
		if err != nil {
			log.Printf("Error reading microsoft bundle cache (ignoring error): %s", err.Error())
			return bundleCache
		}
	}
	return bundleCache
}

func saveMicrosoftBundleCache(cache *microsoftBundleCacheType) {
	f, err := os.OpenFile(microsoftBundleCacheName+"_atomic", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Printf("Error saving microsoft bundle cache (ignoring error): %s", err.Error())
		os.Remove(microsoftBundleCacheName + "_atomic")
		return
	}
	if err := json.NewEncoder(f).Encode(cache); err != nil {
		log.Printf("Error saving microsoft bundle cache (ignoring error): %s", err.Error())
		os.Remove(microsoftBundleCacheName + "_atomic")
		return
	}
	f.Close()
	if err := os.Rename(microsoftBundleCacheName+"_atomic", microsoftBundleCacheName); err != nil {
		log.Printf("Error saving microsoft bundle cache (ignoring error): %s", err.Error())
		os.Remove(microsoftBundleCacheName + "_atomic")
		os.Remove(microsoftBundleCacheName)
	}
}
