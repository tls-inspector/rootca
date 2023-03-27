package main

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var Version = "undefined"

func main() {
	parseArgs()

	start := time.Now()

	log.Printf("rootca version %s\n", Version)

	validateWorkdir()

	if _, err := os.Stat(".force_update"); err == nil {
		forceUpdate = true
		os.Remove(".force_update")
	}

	metadata, err := readMetadata()
	if err != nil {
		log.Fatalf("Error reading bundle metadata file: %s", err.Error())
	}

	var mozillaMetadata *VendorMetadata
	var microsoftMetadata *VendorMetadata
	var googleMetadata *VendorMetadata
	var appleMetadata *VendorMetadata
	var tlsinspectorMetadata *VendorMetadata

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

		if err := signBundle(MozillaBundleName); err != nil {
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

		if err := signBundle(MicrosoftBundleName); err != nil {
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

		if err := signBundle(GoogleBundleName); err != nil {
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

		if err := signBundle(AppleBundleName); err != nil {
			log.Fatalf("Error signing apple bundle: %s", err.Error())
		}

		appleMetadata = newAppleMetadata
	}()

	wg.Wait()

	// Build TLS Inspector bundle after all others
	if metadata != nil {
		tlsinspectorMetadata = &metadata.TLSInspector
	}
	newTLSInspectorMetadata, err := buildTLSInspectorBundle(tlsinspectorMetadata)
	if err != nil {
		log.Fatalf("Error updating tlsinspector bundle: %s", err.Error())
	}
	if err := signBundle(TLSInspectorBundleName); err != nil {
		log.Fatalf("Error signing tlsinspector bundle: %s", err.Error())
	}
	tlsinspectorMetadata = newTLSInspectorMetadata

	newMetadata := BundleMetadata{
		Apple:        *appleMetadata,
		Google:       *googleMetadata,
		Microsoft:    *microsoftMetadata,
		Mozilla:      *mozillaMetadata,
		TLSInspector: *tlsinspectorMetadata,
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

func validateWorkdir() {
	if workdir == "." {
		return
	}

	info, err := os.Stat(workdir)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Error validating workdir '%s': %s", workdir, err.Error())
	}
	if info != nil && !info.IsDir() {
		log.Fatalf("Workdir is not a directory %s", workdir)
	}
	if os.IsNotExist(err) {
		if err := os.Mkdir(workdir, os.ModePerm); err != nil {
			log.Fatalf("Error creating workdir '%s': %s", workdir, err.Error())
		}
	}
	if err := os.Chdir(workdir); err != nil {
		log.Fatalf("Error moving into workdir '%s': %s", workdir, err.Error())
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	wd, err = filepath.Abs(wd)
	if err != nil {
		panic(err)
	}
	log.Printf("Working in directory %s", wd)
}