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
	Calls map[Call]int
}

//
// Create a new, empty CallGraph with enough capacity to hold some calls.
//
func NewCallGraph() CallGraph {
	return CallGraph{
		make(map[string]GraphNode),
		make(map[Call]int),
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
	cg.Calls[Call{caller, callee}] += 1
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

	for call, count := range g.Calls {
		cg.Calls[call] += count
	}

	return nil
}

//
// A node in a call graph.
//
// This is derived from a call site or other program location, but can have
// an arbitrary name and description appropriate to a particular analysis.
//
type GraphNode struct {
	Name        string
	Description string
	Location    SourceLocation

	// A vulnerability (current or previous) is known at this location.
	CVE []CVE

	// The name of this node's sandbox (or the empty string if unsandboxed).
	Sandbox string

	// The name of the sandbox(es) that own the data being accessed.
	Owners []string

	Tags map[string]bool
}

//
// Construct a GraphViz Dot description of a GraphNode.
//
// This applies SOAAP-specific styling depending on a node's tags.
//
func (n GraphNode) Dot() string {
	attrs := map[string]interface{}{
		"label": n.Description,
		"style": "filled",
	}

	if len(n.CVE) > 0 {
		attrs["label"] = fmt.Sprintf("%s\\n%s", n.CVE, n.Description)
	}

	switch true {
	case len(n.CVE) > 0 && n.Sandbox != "":
		// A vulnerability has been mitigated through sandboxing!
		attrs["fillcolor"] = "#ffff66cc"
		attrs["shape"] = "octagon"

	case len(n.CVE) > 0:
		// A vulnerability exists/existed outside a sandbox.
		attrs["fillcolor"] = "#ff9999cc"
		attrs["shape"] = "doubleoctagon"

	case len(n.Owners) > 0:
		// Sandbox-private data was accessed outside the sandbox.
		attrs["fillcolor"] = "#ff99cccc"
		attrs["shape"] = "invhouse"

	case n.Sandbox != "":
		attrs["fillcolor"] = "#99ff9999"
		attrs["style"] = "dashed,filled"

	default:
		attrs["fillcolor"] = "#cccccccc"
	}

	return fmt.Sprintf("\"%s\" %s;", n.Name, dotAttrs(attrs))
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

// Output GraphViz for a Call.
func (c Call) Dot(graph CallGraph, weight int) string {
	caller := graph.Nodes[c.Caller]
	callee := graph.Nodes[c.Callee]

	attrs := map[string]interface{}{
		"label":    caller.Location.String(),
		"penwidth": weight,
		"weight":   weight,
	}

	return fmt.Sprintf("\"%s\" -> \"%s\" %s;\n",
		caller.Name, callee.Name, dotAttrs(attrs))
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

			var node GraphNode
			node.Name = cs.String() + "_" + v.Sandbox
			node.Description = desc
			node.Location = cs.Location
			node.Sandbox = v.Sandbox

			return key, node
		}

		id, top := fn(v.CallSite)
		top.CVE = v.CVE
		graph.Nodes[id] = top

		graph.Union(trace.graph(id, results.Traces, fn))
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

			var node GraphNode
			node.Name = cs.String() + "_" + sandboxes
			node.Description = desc
			node.Location = cs.Location

			return key, node
		}

		id, top := fn(a.CallSite)
		top.Owners = a.Sandboxes
		graph.Nodes[id] = top

		graph.Union(trace.graph(id, results.Traces, fn))

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
func (t CallTrace) graph(top string, traces []CallTrace, nm callSiteLabeler) CallGraph {
	graph := NewCallGraph()
	callee := top

	t.Foreach(traces, func(cs CallSite) {
		identifier, node := nm(cs)
		graph.Nodes[identifier] = node

		caller := identifier
		graph.AddCall(caller, callee)
		callee = caller
	})

	return graph
}

//
// Format a map as a GraphViz attribute list.
//
func dotAttrs(attrs map[string]interface{}) string {
	fields := make([]string, len(attrs))

	i := 0
	for k, v := range attrs {
		switch v.(type) {
		case string:
			v = fmt.Sprintf("\"%s\"", v)
		}

		fields[i] = fmt.Sprintf("\"%s\" = %v", k, v)
		i++
	}

	return fmt.Sprintf("[ %s ]", strings.Join(fields, ", "))
}
