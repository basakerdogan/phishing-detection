package main

import (
	"flag"
	"fmt"
	"github.com/basakerdogan/eml/detect"
	"github.com/sg3des/eml"
	"log"
	"os"
)

func main() {
	// Get the path of eml file using command line arguments
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("eml file not specified")
	}

	// Read the eml file
	content, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal("FATAL: Could not read content of the file", err)
	}

	// Parse the eml file
	msg, err := eml.ParseRaw(content)
	if err != nil {
		log.Fatal("FATAL: Could not parse content due to error", err)
	}

	// Process the eml file
	email, err := eml.Process(msg)
	if err != nil {
		log.Fatal("FATAL: Could not process the email", err)
	}

	// Check for suspicious words
	suspiciousWordsFound, ok := detect.CheckForSuspiciousWords(&email)
	if ok {
		fmt.Printf("WARNING: Suspicious words found in the email: %v\n", suspiciousWordsFound)
	}

	// Check sender validity
	detect.CheckSenderValidity(&email)
}
