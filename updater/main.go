package main

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var Version = "dev"

func main() {
	parseArgs()

	start := time.Now()

	log.Printf("rootca version %s\n", Version)

	if len(publicKeyBytes) > 0 && len(privateKeyBytes) > 0 {
		log.Printf("signing enabled, using public key:\n%s", publicKeyBytes)
	}

	validateWorkdir()

	if _, err := os.Stat(".force_update"); err == nil {
		forceUpdate = true
		os.Remove(".force_update")
	}

	metadata, err := readMetadata()
	if err != nil {
		logFatal("Error reading bundle metadata file: %s", err.Error())
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
			logFatal("Error updating mozilla bundle: %s", err.Error())
		}

		if err := signBundle(MozillaBundleName); err != nil {
			logFatal("Error signing mozilla bundle: %s", err.Error())
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
			logFatal("Error updating microsoft bundle: %s", err.Error())
		}

		if err := signBundle(MicrosoftBundleName); err != nil {
			logFatal("Error signing microsoft bundle: %s", err.Error())
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
			logFatal("Error updating google bundle: %s", err.Error())
		}

		if err := signBundle(GoogleBundleName); err != nil {
			logFatal("Error signing google bundle: %s", err.Error())
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
			logFatal("Error updating apple bundle: %s", err.Error())
		}

		if err := signBundle(AppleBundleName); err != nil {
			logFatal("Error signing apple bundle: %s", err.Error())
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
		logFatal("Error updating tlsinspector bundle: %s", err.Error())
	}
	if err := signBundle(TLSInspectorBundleName); err != nil {
		logFatal("Error signing tlsinspector bundle: %s", err.Error())
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
		logFatal("Error writing metadata file: %s", err.Error())
	}

	if err := signFile(BundleMetadataName); err != nil {
		logFatal("Error signing bundle metadata: %s", err.Error())
	}

	if err := ExportReport(); err != nil {
		logFatal("Error exporting certificate report: %s", err.Error())
	}

	log.Printf("Finished in %s\n", time.Since(start).String())
}

func validateWorkdir() {
	if workdir == "." {
		return
	}

	info, err := os.Stat(workdir)
	if err != nil && !os.IsNotExist(err) {
		logFatal("Error validating workdir '%s': %s", workdir, err.Error())
	}
	if info != nil && !info.IsDir() {
		logFatal("Workdir is not a directory %s", workdir)
	}
	if os.IsNotExist(err) {
		if err := os.Mkdir(workdir, os.ModePerm); err != nil {
			logFatal("Error creating workdir '%s': %s", workdir, err.Error())
		}
	}
	if err := os.Chdir(workdir); err != nil {
		logFatal("Error moving into workdir '%s': %s", workdir, err.Error())
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
