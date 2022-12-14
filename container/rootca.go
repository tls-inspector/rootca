package main

import (
	"log"
	"sync"
	"time"
)

var Version = "undefined"

func main() {
	start := time.Now()

	log.Printf("rootca version %s\n", Version)

	metadata, err := readMetadata()
	if err != nil {
		log.Fatalf("Error reading bundle metadata file: %s", err.Error())
	}

	var mozillaMetadata *VendorMetadata
	var microsoftMetadata *VendorMetadata
	var googleMetadata *VendorMetadata
	var appleMetadata *VendorMetadata

	wg := &sync.WaitGroup{}
	wg.Add(4)

	go func() {
		defer wg.Done()
		if metadata != nil {
			mozillaMetadata = &metadata.Mozilla
		}

		newMozillaMetadata, err := buildMozillaBundle(mozillaMetadata)
		if err != nil {
			log.Fatalf("Error updating mozilla bundle: %s", err.Error())
		}

		if err := signFile(MozillaBundleName); err != nil {
			log.Fatalf("Error signing mozilla bundle: %s", err.Error())
		}

		mozillaMetadata = newMozillaMetadata
	}()

	go func() {
		defer wg.Done()
		if metadata != nil {
			microsoftMetadata = &metadata.Microsoft
		}

		newMicrosoftMetadata, err := buildMicrosoftBundle(microsoftMetadata)
		if err != nil {
			log.Fatalf("Error updating microsoft bundle: %s", err.Error())
		}

		if err := signFile(MicrosoftBundleName); err != nil {
			log.Fatalf("Error signing microsoft bundle: %s", err.Error())
		}

		microsoftMetadata = newMicrosoftMetadata
	}()

	go func() {
		defer wg.Done()
		if metadata != nil {
			googleMetadata = &metadata.Google
		}

		newGoogleMetadata, err := buildGoogleBundle(googleMetadata)
		if err != nil {
			log.Fatalf("Error updating google bundle: %s", err.Error())
		}

		if err := signFile(GoogleBundleName); err != nil {
			log.Fatalf("Error signing google bundle: %s", err.Error())
		}

		googleMetadata = newGoogleMetadata
	}()

	go func() {
		defer wg.Done()
		if metadata != nil {
			appleMetadata = &metadata.Apple
		}

		newAppleMetadata, err := buildAppleBundle(appleMetadata)
		if err != nil {
			log.Fatalf("Error updating apple bundle: %s", err.Error())
		}

		if err := signFile(AppleBundleName); err != nil {
			log.Fatalf("Error signing apple bundle: %s", err.Error())
		}

		appleMetadata = newAppleMetadata
	}()

	wg.Wait()

	newMetadata := BundleMetadata{
		Mozilla:   *mozillaMetadata,
		Microsoft: *microsoftMetadata,
		Google:    *googleMetadata,
		Apple:     *appleMetadata,
	}

	if err := writeMetadata(newMetadata); err != nil {
		log.Fatalf("Error writing metadata file: %s", err.Error())
	}

	if err := signFile(BundleMetadataName); err != nil {
		log.Fatalf("Error signing bundle metadata: %s", err.Error())
	}

	if err := ExportReport(); err != nil {
		log.Fatalf("Error exporting certificate report: %s", err.Error())
	}

	log.Printf("Finished in %s\n", time.Since(start).String())
}
