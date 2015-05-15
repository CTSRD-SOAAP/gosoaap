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
	// Open input, output files:
	//
	f, err := os.Open(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

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
	// Parse the JSON:
	//
	results, err := soaap.ParseJSON(f, func(progress string) {
		fmt.Println(progress)
		os.Stdout.Sync()
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

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
