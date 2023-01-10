package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"time"
)

const MicrosoftBundleName = "microsoft_ca_bundle.p7b"

func buildMicrosoftBundle(metadata *VendorMetadata) (*VendorMetadata, error) {
	caCSV, err := httpGetString("https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV")
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(strings.NewReader(caCSV))

	type microsoftCert struct {
		Status   string
		SHA1     string
		SHA256   string
		MSEKU    string
		NotAfter time.Time
	}
	certificates := []microsoftCert{}
	thumbprintMap := map[string]bool{}
	thumbprintSlice := []string{}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		status := record[0]
		certSHA1 := record[3]
		certSHA256 := record[4]
		msEKU := record[5]
		notAfterStr := record[7]

		if status == "Disabled" {
			continue // Skip disabled certificates
		}

		// 2025 Jul 23
		notAfter, err := time.Parse("2006 Jan 02", notAfterStr)
		if err != nil {
			continue
		}

		if time.Now().UTC().After(notAfter) {
			continue // Skip expired certificates
		}

		if !strings.Contains(msEKU, "Server Authentication") {
			// Skip certificates that Microsoft has not marked as being suitable for server authentication
			// (note that these EKUs don't appear on the certificate itself)
			continue
		}

		certificates = append(certificates, microsoftCert{
			Status:   status,
			SHA1:     certSHA1,
			SHA256:   certSHA256,
			MSEKU:    msEKU,
			NotAfter: notAfter,
		})
		thumbprintMap[certSHA256] = true
		thumbprintSlice = append(thumbprintSlice, certSHA256)
	}

	currentSHA := checksumCertShaList(thumbprintSlice)
	if metadata != nil {
		if metadata.Key == currentSHA {
			log.Printf("Microsoft bundle is up-to-date")
			return metadata, nil
		}
		log.Printf("Detected changes to Microsoft bundle. LastSHA='%s' LatestSHA='%s'", metadata.Key, currentSHA)
	}
	log.Printf("Building Microsoft CA bundle")

	tmpDir, err := os.MkdirTemp("", "microsoft")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	if fileExists(MicrosoftBundleName) {
		if err := extractP7B(MicrosoftBundleName, tmpDir); err != nil {
			return nil, fmt.Errorf("error extracting microsoft certificates: %s", err.Error())
		}
	}

	certPaths := make([]string, len(certificates))
	for i, cert := range certificates {
		certPath := path.Join(tmpDir, cert.SHA256+".crt")

		if fileExists(certPath) {
			if !verifyCertPEMSHA(certPath, cert.SHA256) {
				log.Printf("Cached Microsoft certificate %s.crt is bad", cert.SHA1)
				os.Remove(certPath)
			} else {
				// Cached cert is good
				certPaths[i] = certPath
				continue
			}
		}

		derCertPath := path.Join(tmpDir, cert.SHA1+".bin")

		if err := downloadFile(fmt.Sprintf("http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/%s.crt", cert.SHA1), derCertPath); err != nil {
			return nil, err
		}
		dlThumbprint, err := convertDerToPem(derCertPath, certPath)
		if err != nil {
			return nil, err
		}
		if dlThumbprint != cert.SHA256 {
			return nil, fmt.Errorf("downloaded certificate verification failed")
		}

		os.Remove(derCertPath)
		log.Printf("Downloaded and converted %s.crt", cert.SHA1)
		certPaths[i] = certPath
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

	os.Remove(MicrosoftBundleName)
	if err := makeP7BFromCerts(certPaths, MicrosoftBundleName); err != nil {
		return nil, err
	}

	hash, err := shaSumFile(MicrosoftBundleName)
	if err != nil {
		return nil, err
	}

	log.Printf("Microsoft CA bundle generated with %d certificates", len(certPaths))

	return &VendorMetadata{
		Date:     time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		Key:      currentSHA,
		SHA256:   hash,
		NumCerts: len(certPaths),
	}, nil
}
