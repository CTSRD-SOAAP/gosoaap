package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CTSRD-SOAAP/gosoaap"
)

func main() {
	//
	// Command-line arguments:
	//
	output := flag.String("output", "-", "output GraphViz file")
	flag.Parse()

	if len(flag.Args()) != 1 {
		printUsage()
		return
	}

	input := flag.Args()[0]

	//
	// Load input file:
	//
	f, err := os.Open(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

	results, err := soaap.LoadResults(f, reportProgress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

	//
	// Open output file:
	//
	var outfile *os.File
	if *output == "-" {
		outfile = os.Stdout
	} else {
		outfile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return
		}
	}
	out := io.Writer(outfile)

	//
	// Encode it as a gob of data:
	//
	fmt.Print("Encoding...")
	encoder := gob.NewEncoder(out)
	encoder.Encode(results)
	fmt.Println(" done.")

	outfile.Sync()
}

func printUsage() {
	fmt.Fprintf(os.Stderr,
		"Usage:  soaap-graph [options] <input file>\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}

func reportProgress(message string) {
	fmt.Println(message)
}
