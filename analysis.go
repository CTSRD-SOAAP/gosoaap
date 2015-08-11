package soaap

import "fmt"

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
//   * ":spec": filter leaf nodes according to "spec":
//     * "+name": keep a leaf node
//     * "*": keep all current leaf nodes (used together with '-', below)
//     * "-name": remove a leaf node
//     * examples:
//       * ":ALL:-foo:-bar" keeps all leaf nodes except "foo" and "bar"
//       * ":+foo:+bar" keeps only "foo" and "bar" leaf nodes
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
