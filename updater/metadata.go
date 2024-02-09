package main

import (
	"encoding/json"
	"os"
	"time"
)

const BundleMetadataName = "bundle_metadata.json"

type BundleMetadata struct {
	Mozilla      VendorMetadata `json:"mozilla"`
	Microsoft    VendorMetadata `json:"microsoft"`
	Google       VendorMetadata `json:"google"`
	Apple        VendorMetadata `json:"apple"`
	TLSInspector VendorMetadata `json:"tls_inspector"`
}

type VendorMetadata struct {
	Date     string                       `json:"date"`
	Key      string                       `json:"key"`
	Bundles  map[string]BundleFingerprint `json:"bundles"`
	NumCerts int                          `json:"num_certs"`
}

func (m VendorMetadata) MustDate() time.Time {
	d, err := time.Parse("2006-01-02T15:04:05Z07:00", m.Date)
	if err != nil {
		panic(err)
	}
	return d
}

type BundleFingerprint struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

func readMetadata() (*BundleMetadata, error) {
	if _, err := os.Stat(BundleMetadataName); err != nil {
		return nil, nil
	}

	f, err := os.OpenFile(BundleMetadataName, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	metadata := BundleMetadata{}
	if err := json.NewDecoder(f).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func writeMetadata(metadata BundleMetadata) error {
	f, err := os.OpenFile(BundleMetadataName+"_atomic", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	j := json.NewEncoder(f)
	j.SetIndent("", "  ")

	if err := j.Encode(metadata); err != nil {
		f.Close()
		return err
	}
	f.Close()

	if err := os.Rename(BundleMetadataName+"_atomic", BundleMetadataName); err != nil {
		return err
	}

	return nil
}
