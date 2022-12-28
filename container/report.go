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
	"sync"
	"time"
)

type ReportCertificate struct {
	Vendor        string
	Name          string
	Serial        []byte
	KeyIdentifier string
	NotBefore     time.Time
	NotAfter      time.Time
	SHA1          string
	SHA256        string
}

var reportLock = &sync.Mutex{}
var Report = []ReportCertificate{}

func CertificatesFromP7(vendor, p7File string) error {
	output, err := exec.Command("openssl", "pkcs7", "-in", p7File, "-print_certs").CombinedOutput()
	if err != nil {
		return err
	}
	pemCerts := extractPemCerts(output)
	for _, pemCert := range pemCerts {
		cert, err := ReportCertificateFromPem(vendor, pemCert)
		if err != nil {
			return err
		}
		reportLock.Lock()
		Report = append(Report, *cert)
		reportLock.Unlock()
	}
	return nil
}

func ReportCertificateFromPem(vendorName string, pemData []byte) (*ReportCertificate, error) {
	certPem, _ := pem.Decode(pemData)
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	s1 := sha1.New()
	s1.Write(cert.Raw)
	s256 := sha256.New()
	s256.Write(cert.Raw)

	return &ReportCertificate{
		Vendor:        vendorName,
		Name:          cert.Subject.ToRDNSequence().String(),
		Serial:        cert.SerialNumber.Bytes(),
		KeyIdentifier: fmt.Sprintf("%X", cert.SubjectKeyId),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		SHA1:          fmt.Sprintf("%X", s1.Sum(nil)),
		SHA256:        fmt.Sprintf("%X", s256.Sum(nil)),
	}, nil
}

func ExportReport() error {
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

	sort.SliceStable(Report, func(i, j int) bool {
		return Report[i].Vendor > Report[j].Vendor && Report[i].Name > Report[j].Name
	})

	for _, cert := range Report {
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
	return nil
}
