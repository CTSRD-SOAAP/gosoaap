package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/CTSRD-SOAAP/gosoaap"
)

var (
	output = flag.String("output", "-", "output file")

	operation = flag.String("operation", "union",
		"the combining operation to perform (union|intersection)")

	intersectionDepth = flag.Int("intersection-depth", 3,
		"how many calls to trace back from a leaf node when looking"+
			" for call graph intersections")
)

func main() {
	flag.Parse()

	//
	// Open input files:
	//
	if len(flag.Args()) < 2 {
		printUsage()
		return
	}

	graphs := make([]soaap.CallGraph, 0, 2)
	for _, filename := range flag.Args() {
		f, err := os.Open(filename)
		if err != nil {
			die("error opening '%s': %s", filename, err)
		}

		graph, err := soaap.LoadGraph(f, report)
		if err != nil {
			die("error loading graph from '%s': %s", filename, err)
		}

		graphs = append(graphs, graph)
	}

	//
	// Open output file:
	//
	out, err := os.Create(*output)
	if err != nil {
		die("error opening '%s': %s", *output, err)
	}

	//
	// Apply the requested combining operation:
	//
	graph := graphs[0]
	for _, g := range graphs[1:] {
		switch *operation {
		case "addintersecting":
			err = graph.AddIntersecting(g, *intersectionDepth)

		case "intersection":
			graph, err = graph.Intersect(g, *intersectionDepth, true)

		case "union":
			err = graph.Union(g)

		default:
			die("Unknown combining operation: '%s'", *operation)
		}
	}

	if err != nil {
		die("error applying '%s': %s", *operation, err)
	}

	nodes, edges, flows := graph.Size()
	fmt.Printf("Final graph has %d nodes, %d edges and %d flows.\n",
		nodes, edges, flows)

	err = graph.Save(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error saving: %s\n", err)
	}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printUsage() {
	fmt.Fprintf(os.Stderr,
		"Usage:  soaap-combine [options] <input files>\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}

func report(progress string) {
	fmt.Println(progress)
	os.Stdout.Sync()
}
