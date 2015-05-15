package soaap

import (
	"encoding/gob"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
)

type CallGraph struct {
	Nodes map[string]GraphNode
	Calls []Call
}

//
// Create a new, empty CallGraph with enough capacity to hold some calls.
//
func NewCallGraph() CallGraph {
	return CallGraph{
		make(map[string]GraphNode),
		make([]Call, 0, 1000),
	}
}

//
// Load a CallGraph from a binary-encoded file.
//
func LoadGraph(f *os.File, report func(string)) (CallGraph, error) {
	var graph CallGraph
	err := gob.NewDecoder(f).Decode(&graph)

	return graph, err
}

func (cg *CallGraph) AddCall(caller string, callee string) {
	cg.Calls = append(cg.Calls, Call{caller, callee})
}

//
// Save a CallGraph to an os.File using a binary encoding.
//
func (cg *CallGraph) Save(f *os.File) error {
	return gob.NewEncoder(f).Encode(cg)
}

//
// Simplify a CallGraph by collapsing call chains and dropping any
// unreferenced calls.
//
func (cg *CallGraph) Simplify() {
}

func (cg *CallGraph) Union(g CallGraph) error {
	for id, node := range g.Nodes {
		// If we already have a GraphNode with this identifier,
		// merge the two descriptions and tag sets.
		if n, have := cg.Nodes[id]; have {
			if n.Name != node.Name {
				return errors.New(fmt.Sprintf(
					"Nodes in CallGraph union have"+
						" same identifier ('%s') but"+
						" different names ('%s' vs '%s')",
					id, n.Name, node.Name))
			}

			if n.Description != node.Description {
				node.Description =
					n.Description + "\\n" + node.Description
			}

			for tag := range n.Tags {
				node.Tags[tag] = true
			}
		}

		cg.Nodes[id] = node
	}

	for _, call := range g.Calls {
		cg.Calls = append(cg.Calls, call)
	}

	return nil
}

func Node(name string, desc string, tags []string) GraphNode {
	node := GraphNode{name, desc, make(map[string]bool)}
	for _, s := range tags {
		node.Tags[s] = true
	}

	return node
}

type GraphNode struct {
	Name        string
	Description string
	Tags        map[string]bool
}

func (n GraphNode) Dot() string {
	return fmt.Sprintf(
		"\"%s\" [ label = \"%s\" ];",
		n.Name, n.Description)
}

func (n GraphNode) HasTag(tag string) bool {
	_, present := n.Tags[tag]
	return present
}

type Call struct {
	// Identifier of the caller.
	Caller string

	// Identifier of the callee.
	Callee string
}

//
// A function that extracts a CallGraph from SOAAP Results.
//
type graphFn func(results Results, progress func(string)) CallGraph

var graphExtractors map[string]graphFn = map[string]graphFn{
	"privaccess": PrivAccessGraph,
	"vuln":       VulnGraph,
}

func GraphAnalyses() []string {
	keys := make([]string, len(graphExtractors))

	i := 0
	for k, _ := range graphExtractors {
		keys[i] = k
		i++
	}

	return keys
}

type callSiteLabeler func(CallSite) (string, GraphNode)

//
// Construct a callgraph from SOAAP's vulnerability analysis.
//
func VulnGraph(results Results, progress func(string)) CallGraph {
	graph := NewCallGraph()

	for _, v := range results.Vulnerabilities {
		trace := results.Traces[v.Trace]

		fn := func(cs CallSite) (string, GraphNode) {
			key := cs.String() + " " + v.Sandbox

			desc := cs.Function
			if v.Sandbox != "" {
				desc += "\\n<<" + v.Sandbox + ">>"
			}

			node := Node(
				cs.String()+"_"+v.Sandbox,
				desc,
				[]string{},
			)

			return key, node
		}

		graph.Union(trace.graph(results.Traces, fn))
	}

	return graph
}

//
// Construct a callgraph of sandbox-private data accesses outside of sandboxes.
//
func PrivAccessGraph(results Results, progress func(string)) CallGraph {
	graph := NewCallGraph()
	accesses := results.PrivateAccess
	total := len(accesses)
	chunk := int(math.Ceil(math.Pow(10, math.Log10(float64(total)/500))))

	go progress(fmt.Sprintf("Processing %d private accesses", total))

	count := 0
	for _, a := range accesses {
		trace := results.Traces[a.Trace]

		fn := func(cs CallSite) (string, GraphNode) {
			sandboxes := strings.Join(a.Sandboxes, ",")
			key := cs.String() + " " + sandboxes

			desc := cs.Function
			if sandboxes != "" {
				desc += "\\n<<" + sandboxes + ">>"
			}

			node := Node(
				cs.String()+"_"+sandboxes,
				desc,
				[]string{},
			)

			return key, node
		}

		graph.Union(trace.graph(results.Traces, fn))

		count++
		if count%chunk == 0 {
			go progress(
				fmt.Sprintf("Processed %d/%d accesses",
					count, total))
		}
	}

	return graph
}

//
// Graph a single CallTrace, using a callSiteLabeler function to convert
// CallSite instances into graph nodes with identifiers, tags, etc.,
// appropriate to the analysis we're performing.
//
func (t CallTrace) graph(traces []CallTrace, nm callSiteLabeler) CallGraph {
	graph := NewCallGraph()
	var callee string

	t.Foreach(traces, func(cs CallSite) {
		identifier, node := nm(cs)
		graph.Nodes[identifier] = node

		caller := identifier

		if callee != "" {
			graph.AddCall(caller, callee)
		}

		callee = caller
	})

	return graph
}
