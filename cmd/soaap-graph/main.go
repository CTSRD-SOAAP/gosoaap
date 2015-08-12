package main

import (
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

var (
	intersectionDepth = flag.Int("intersection-depth", 3,
		"how many calls to trace back from a leaf node when looking"+
			" for call graph intersections")
)

func main() {
	//
	// Command-line arguments:
	//
	legend := flag.Bool("legend", false,
		"emit a Dot legend rather than an actual graph")

	analyses := Analyses{"vuln"}
	flag.Var(&analyses, "analyses",
		"SOAAP analysis results to graph (options: "+
			strings.Join(soaap.GraphAnalyses(), ", ")+
			")")

	groupBy := flag.String("group-by", "", "group nodes by file, sandbox, etc.")

	output := flag.String("output", "-", "output file")

	binout := flag.Bool("binary", false, "write binary output")
	simplify := flag.Bool("simplify", false, "simplify callgraph")

	flag.Parse()

	var input string
	switch len(flag.Args()) {
	case 0:
		input = "-"

	case 1:
		input = flag.Args()[0]

	default:
		printUsage()
		return
	}

	//
	// Load input file:
	//
	var f *os.File
	var err error

	if input == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return
		}
	}

	//
	// Open output file:
	//
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
	// The call/dataflow graph to transform and output.
	//
	var graph soaap.CallGraph

	//
	// Special case: legend of possible node types.
	//
	if *legend {
		graph = soaap.Legend()

	} else if strings.HasSuffix(f.Name(), ".graph") {

		// Load binary graph file.
		report(fmt.Sprintf("Loading binary graph data from '%s'...", f.Name()))
		graph, err = soaap.LoadGraph(f, report)

	} else {

		// Load SOAAP results.
		report(fmt.Sprintf("Loading SOAAP results from '%s'...", f.Name()))
		graph, err = analyzeResultsFile(f, analyses)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nerror: %s\n", err)
		os.Exit(1)
	}

	nodes, edges, flows := graph.Size()
	fmt.Printf("Result: %d nodes, %d calls and %d flows\n",
		nodes, edges, flows)

	//
	// Apply any requested transformations:
	//
	if *simplify {
		graph = graph.Simplified()
		nodes, edges, flows = graph.Size()
		fmt.Printf("Simplified: %d nodes, %d calls and %d flows\n",
			nodes, edges, flows)
	}

	//
	// Output the results:
	//
	if *binout {
		err = graph.Save(out)
	} else {
		err = graph.WriteDot(out, *groupBy)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %s\n", err)
		os.Exit(1)
	}
}

func analyzeResultsFile(f *os.File, analyses []string) (soaap.CallGraph, error) {
	//
	// Combine callgraphs of the requested analyses:
	//
	results, err := soaap.LoadResults(f, report)
	if err != nil {
		return soaap.CallGraph{}, err
	}

	fmt.Println("Initializing empty call graph")
	graph := soaap.NewCallGraph()

	for _, analysis := range analyses {
		graph, err = soaap.ApplyAnalysis(
			analysis, &graph, &results, *intersectionDepth, report)
	}

	return graph, err
}

func printUsage() {
	fmt.Fprintf(os.Stderr,
		"Usage:  soaap-graph [options] <input file>\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}

func report(progress string) {
	fmt.Println(progress)
	os.Stdout.Sync()
}
