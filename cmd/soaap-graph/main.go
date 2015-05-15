package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/CTSRD-SOAAP/gosoaap"
)

type Analyses []string

func (a *Analyses) Set(value string) error {
	*a = strings.Split(value, ",")
	return nil
}

func (a Analyses) String() string {
	return strings.Join(a, ", ")
}

func main() {
	//
	// Command-line arguments:
	//
	analyses := Analyses{"vuln"}
	flag.Var(&analyses, "analyses", "SOAAP analysis results to graph")

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

	var out *os.File
	if *output == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return
		}
	}

	//
	// Load the data (JSON- or gob-encoded):
	//
	var results soaap.Results

	if strings.HasSuffix(input, ".gob") {
		decoder := gob.NewDecoder(f)
		err = decoder.Decode(&results)
	} else {
		results, err = soaap.ParseJSON(f, func(progress string) {
			fmt.Println(progress)
			os.Stdout.Sync()
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

	graph := soaap.NewCallGraph()
	for _, a := range analyses {
		fn, ok := soaap.GraphFns[a]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown analysis: '%s'", a)
			return
		}

		graph.Union(fn(results))
	}

	fmt.Fprintln(out, "digraph {")
	fmt.Fprintln(out, dotHeader())

	for _, n := range graph.Nodes {
		fmt.Fprintf(out, "	%s\n", n.Dot())
	}

	for _, c := range graph.Calls {
		caller := graph.Nodes[c.Caller]
		callee := graph.Nodes[c.Callee]

		fmt.Fprintf(out, "	\"%s\" -> \"%s\";\n",
			caller.Name, callee.Name)
	}

	fmt.Fprintf(out, "}\n")
}

func dotHeader() string {
	return `

	node [ fontname = "Inconsolata" ];
	edge [ fontname = "Avenir" ];

	labeljust = "l";
	labelloc = "b";
	rankdir = "BT";

`
}

func printUsage() {
	fmt.Fprintf(os.Stderr,
		"Usage:  soaap-graph [options] <input file>\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}
