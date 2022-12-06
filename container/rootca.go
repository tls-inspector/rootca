package main

import "log"

var Version = "undefined"

func main() {
	log.Printf("rootca version %s\n", Version)

	metadata, err := readMetadata()
	if err != nil {
		log.Fatalf("Error reading bundle metadata file: %s", err.Error())
	}

	var mozillaMetadata *VendorMetadata
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

	var microsoftMetadata *VendorMetadata
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

	newMetadata := BundleMetadata{
		Mozilla:   *newMozillaMetadata,
		Microsoft: *newMicrosoftMetadata,
	}

	if err := writeMetadata(newMetadata); err != nil {
		log.Fatalf("Error writing metadata file: %s", err.Error())
	}

	if err := signFile(BundleMetadataName); err != nil {
		log.Fatalf("Error signing bundle metadata: %s", err.Error())
	}

	log.Println("Finished")
}
