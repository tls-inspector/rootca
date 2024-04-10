package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
)

var forceUpdate = false
var opensslPath = ""
var cabextractPath = ""
var workdir = "bundles"
var publicKeyBytes []byte
var privateKeyBytes []byte

const (
	envSigningPubKey  = "ROOTCA_SIGNING_PUBLIC_KEY"
	envSigningPrivKey = "ROOTCA_SIGNING_PRIVATE_KEY"
)

func parseArgs() {
	args := os.Args
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg[0] == '-' {
			switch arg {
			case "--public-key-path":
				if len(args)-1 == i {
					fmt.Fprintf(os.Stderr, "Arg %s requires a value\n", arg)
					os.Exit(1)
				}
				b, err := os.ReadFile(args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading public key file %s: %s", args[i+1], err.Error())
					os.Exit(1)
				}
				publicKeyBytes = b
				i++
			case "--private-key-path":
				if len(args)-1 == i {
					fmt.Fprintf(os.Stderr, "Arg %s requires a value\n", arg)
					os.Exit(1)
				}
				b, err := os.ReadFile(args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading private key file %s: %s", args[i+1], err.Error())
					os.Exit(1)
				}
				privateKeyBytes = b
				i++
			case "--openssl-path":
				if len(args)-1 == i {
					fmt.Fprintf(os.Stderr, "Arg %s requires a value\n", arg)
					os.Exit(1)
				}
				opensslPath = args[i+1]
				i++
			case "--cabextract-path":
				if len(args)-1 == i {
					fmt.Fprintf(os.Stderr, "Arg %s requires a value\n", arg)
					os.Exit(1)
				}
				cabextractPath = args[i+1]
				i++
			case "--force-update":
				forceUpdate = true
			case "--help":
				fmt.Printf(`Usage %s [options] [workdir]

Workdir: The directory where the bundles will be saved. Defaults to "bundles". Will create the directory if it does not exist.

Options:
 --public-key-path   Optionally specify a path to a PEM-encoded signing public key.
 --private-key-path  Optionally specify a path to a PEM-encoded signing private key.
 --openssl-path      Optionally specify the path to openssl executable. Defaults to looking in $PATH.
 --cabextract-path   Optionally specify the path to cabextract executable. Defaults to looking in $PATH.
 --force-update      Forcefully trigger an update of all bundles. By default bundles will only be updated if changes are detected.

Environment Variables:
 %s   Specify the public key PEM contents. Escape newlines with double backslashes.
 %s  Specify the private key PEM contents. Escape newlines with double backslaces.
`, os.Args[0], envSigningPubKey, envSigningPrivKey)
				os.Exit(0)
			}
		} else {
			workdir = arg
		}
		i++
	}

	if opensslPath == "" {
		openssl, err := exec.LookPath("openssl")
		if err != nil {
			log.Fatalf("Cannot find openssl in PATH")
		}
		opensslPath = openssl
	}
	if cabextractPath == "" {
		cabextract, err := exec.LookPath("cabextract")
		if err != nil {
			log.Fatalf("Cannot find cabextract in PATH")
		}
		cabextractPath = cabextract
	}

	if len(publicKeyBytes) == 0 && os.Getenv(envSigningPubKey) != "" {
		keyBase64 := os.Getenv(envSigningPubKey)

		if _, err := base64.StdEncoding.DecodeString(keyBase64); err != nil {
			log.Fatalf("Invalid public key value in %s", envSigningPubKey)
		}

		keyStr := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", keyBase64)
		publicKeyBytes = []byte(keyStr)
	}
	if len(privateKeyBytes) == 0 && os.Getenv(envSigningPrivKey) != "" {
		keyBase64 := os.Getenv(envSigningPrivKey)

		if _, err := base64.StdEncoding.DecodeString(keyBase64); err != nil {
			log.Fatalf("Invalid public key value in %s", envSigningPrivKey)
		}

		keyStr := fmt.Sprintf("-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----", keyBase64)
		privateKeyBytes = []byte(keyStr)
	}
}
