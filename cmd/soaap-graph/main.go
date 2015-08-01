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
	// Is the input file a binary-encoded graph or a set of SOAAP results
	// that we need to extract a graph from?
	//
	var graph soaap.CallGraph

	if strings.HasSuffix(f.Name(), ".graph") {
		graph, err = soaap.LoadGraph(f, report)

	} else {
		graph, err = analyzeResultsFile(f, analyses)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

	nodes, edges := graph.Size()
	fmt.Printf("Result: %d nodes and %d edges\n", nodes, edges)

	//
	// Apply any requested transformations:
	//
	if *simplify {
		graph = graph.Simplified()
		nodes, edges = graph.Size()
		fmt.Printf("Simplified: %d nodes and %d edges\n", nodes, edges)
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
		var combineGraphs func(soaap.CallGraph) error
		var description string

		switch analysis[0] {
		case '+':
			description = "Adding"
			combineGraphs = graph.Union
			analysis = analysis[1:]

		case '.':
			description = fmt.Sprintf("Adding intersection (depth %d) with",
				intersectionDepth)

			combineGraphs = func(g soaap.CallGraph) error {
				return graph.AddIntersecting(g,
					*intersectionDepth)
			}
			analysis = analysis[1:]

		case '^':
			description = fmt.Sprintf("Intersecting (depth %d) with",
				intersectionDepth)

			combineGraphs = func(g soaap.CallGraph) error {
				graph, err = graph.Intersect(g,
					*intersectionDepth, true)
				return err
			}
			analysis = analysis[1:]

		default:
			description = "Adding"
			combineGraphs = graph.Union
		}

		g, err := results.ExtractGraph(analysis, report)
		if err != nil {
			return graph, err
		}

		nodes, edges := g.Size()
		report(fmt.Sprintf("%s '%s' analysis (%d nodes, %d edges)",
			description, analysis, nodes, edges))

		err = combineGraphs(g)
		if err != nil {
			break
		}
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
