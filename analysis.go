package soaap

import (
	"fmt"
	"regexp"
	"strings"
)

// A function that can produce a CallGraph when given a CallGraph.
type Analyser func(*CallGraph) (CallGraph, error)

//
// Apply an analysis to a CallGraph using an already-loaded Results file.
//
// Possible analyses include:
//
//   * "+graphtype": union with "graphtype" from the Results
//   * "^graphtype": intersection with "graphtype" from the Results
//   * ".graphtype": union-of-intersection with "graphtype"
//   * ":spec": filter leaf nodes according to "spec" (see Filter)
//
// where "graphtype" can be:
//   * vuln: the callgraph of previously-vulnerable code
//   * privaccess: the call-and-data-flow graph of access to private data
//
func ApplyAnalysis(spec string, cg *CallGraph, results *Results,
	depth int, report func(string)) (CallGraph, error) {

	union := func(g *CallGraph) (CallGraph, error) {
		err := cg.Union(*g)
		return *cg, err
	}

	switch spec[0] {
	case '+':
		report("Adding " + spec[1:])
		return extractAndCombine(spec[1:], results, report, union)

	case '^':
		report(fmt.Sprintf("Intersecting (depth %d) with %s", depth, spec[1:]))
		return extractAndCombine(spec[1:], results, report,
			func(g *CallGraph) (CallGraph, error) {
				return cg.Intersect(*g, depth, true)
			})

	case '.':
		report(fmt.Sprintf("Adding intersection (depth %d) with %s", depth, spec[1:]))
		return extractAndCombine(spec[1:], results, report,
			func(g *CallGraph) (CallGraph, error) {
				err := cg.AddIntersecting(*g, depth)
				return *cg, err
			})

	case ':':
		report("Filtering with '" + spec + "'")
		return Filter(*cg, spec[1:])

	default:
		report("Adding " + spec)
		return extractAndCombine(spec, results, report, union)
	}
}

func extractAndCombine(graphname string, r *Results, report func(string),
	analyse Analyser) (CallGraph, error) {

	g, err := r.ExtractGraph(graphname, report)
	if err != nil {
		return CallGraph{}, err
	}

	nodes, edges, flows := g.Size()
	report(fmt.Sprintf("'%s': %d nodes, %d edges, %d flows",
		graphname, nodes, edges, flows))

	return analyse(&g)
}

//
// Filter a graph according to a colon-separated list of filter specifications,
// where each element can be:
//
//  * "*": add all leaf nodes in the graph
//  * "+regex": keep leaf nodes that match a pattern
//  * "-regex": remove leaf nodes that match a pattern
//
// Examples:
//
//  ":*:-foo:-bar" keeps all leaf nodes except "foo" and "bar"
//
//  ":+.*foo.*:+.*bar.*" keeps only those leaf nodes (plus ancestors)
//  with "foo" and "bar" in their names
//
func Filter(cg CallGraph, spec string) (CallGraph, error) {
	leaves := make(strset)

	for _, s := range strings.Split(spec, ":") {
		if s == "*" {
			leaves = leaves.Union(cg.leaves)
			continue
		}

		var add bool
		switch s[0] {
		case '+':
			add = true

		case '-':
			add = false

		default:
			return CallGraph{},
				fmt.Errorf("unknown filter clause: '%s'", s)
		}

		pattern, err := regexp.Compile(s[1:])
		if err != nil {
			return cg, err
		}

		for leaf := range cg.leaves {
			if pattern.MatchString(leaf) {
				if add {
					leaves.Add(leaf)
				} else {
					leaves.Remove(leaf)
				}
			}
		}
	}

	keep := make(strset)
	for leaf := range leaves {
		keep = keep.Union(cg.Ancestors(leaf, -1))
	}

	return cg.Filter(keep), nil
}
