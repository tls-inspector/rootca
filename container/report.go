package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	csvEncoder "encoding/csv"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"
)

func ExportReport() error {
	type tReportCertificate struct {
		Vendor        string
		Name          string
		Serial        []byte
		KeyIdentifier string
		NotBefore     time.Time
		NotAfter      time.Time
		SHA1          string
		SHA256        string
	}

	certificatesFromP7 := func(vendor, p7File string) ([]tReportCertificate, error) {
		output, err := exec.Command("openssl", "pkcs7", "-in", p7File, "-print_certs").CombinedOutput()
		if err != nil {
			return nil, err
		}
		pemCerts := extractPemCerts(output)
		reportCertificates := []tReportCertificate{}
		for _, pemCert := range pemCerts {
			certPem, _ := pem.Decode(pemCert)
			cert, err := x509.ParseCertificate(certPem.Bytes)
			if err != nil {
				return nil, err
			}

			s1 := sha1.New()
			s1.Write(cert.Raw)
			s256 := sha256.New()
			s256.Write(cert.Raw)

			reportCertificates = append(reportCertificates, tReportCertificate{
				Vendor:        vendor,
				Name:          cert.Subject.ToRDNSequence().String(),
				Serial:        cert.SerialNumber.Bytes(),
				KeyIdentifier: fmt.Sprintf("%X", cert.SubjectKeyId),
				NotBefore:     cert.NotBefore,
				NotAfter:      cert.NotAfter,
				SHA1:          fmt.Sprintf("%X", s1.Sum(nil)),
				SHA256:        fmt.Sprintf("%X", s256.Sum(nil)),
			})
		}
		sort.Slice(reportCertificates, func(i, j int) bool {
			return reportCertificates[i].SHA256 > reportCertificates[j].SHA256
		})
		return reportCertificates, nil
	}

	appleCertificates, err := certificatesFromP7("Apple", AppleBundleName)
	if err != nil {
		return fmt.Errorf("apple: %s", err.Error())
	}
	googleCertificates, err := certificatesFromP7("Google", GoogleBundleName)
	if err != nil {
		return fmt.Errorf("google: %s", err.Error())
	}
	microsoftCertificates, err := certificatesFromP7("Microsoft", MicrosoftBundleName)
	if err != nil {
		return fmt.Errorf("microsoft: %s", err.Error())
	}
	mozillaCertificates, err := certificatesFromP7("Mozilla", MozillaBundleName)
	if err != nil {
		return fmt.Errorf("mozilla: %s", err.Error())
	}
	tlsinspectorCertificates, err := certificatesFromP7("TLSInspector", TLSInspectorBundleName)
	if err != nil {
		return fmt.Errorf("tlsinspector: %s", err.Error())
	}

	os.Remove("certificates.csv")
	f, err := os.OpenFile("certificates.csv", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	csv := csvEncoder.NewWriter(f)
	err = csv.Write([]string{"Vendor", "Name", "Serial", "KeyIdentifier", "NotBefore", "NotAfter", "SHA1", "SHA256"})
	if err != nil {
		return err
	}

	for _, certs := range [][]tReportCertificate{appleCertificates, googleCertificates, microsoftCertificates, mozillaCertificates, tlsinspectorCertificates} {
		for _, cert := range certs {
			err = csv.Write([]string{
				cert.Vendor,
				cert.Name,
				fmt.Sprintf("%X", cert.Serial),
				cert.KeyIdentifier,
				cert.NotBefore.Format(time.RFC3339),
				cert.NotAfter.Format(time.RFC3339),
				cert.SHA1,
				cert.SHA256,
			})
			if err != nil {
				return err
			}
		}
		csv.Flush()
	}

	return nil
}
