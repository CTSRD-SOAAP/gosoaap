package soaap

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

type CallGraph struct {
	nodes  map[string]GraphNode
	roots  strset
	leaves strset
	calls  map[Call]int
}

//
// Create a new, empty CallGraph with enough capacity to hold some calls.
//
func NewCallGraph() CallGraph {
	return CallGraph{
		make(map[string]GraphNode),
		make(strset),
		make(strset),
		make(map[Call]int),
	}
}

//
// Load a CallGraph from a binary-encoded file.
//
func LoadGraph(f *os.File, report func(string)) (CallGraph, error) {
	var cg CallGraph

	dec := gob.NewDecoder(f)

	if err := dec.Decode(&cg.nodes); err != nil {
		return cg, err
	}

	if err := dec.Decode(&cg.roots); err != nil {
		return cg, err
	}

	if err := dec.Decode(&cg.leaves); err != nil {
		return cg, err
	}

	if err := dec.Decode(&cg.calls); err != nil {
		return cg, err
	}

	return cg, nil
}

func (cg *CallGraph) AddCall(caller string, callee string) {
	cg.calls[Call{caller, callee}] += 1

	// This idiom (copy, modify, update) is terribly tedious, but
	// Go maps always return copies rather than references.
	c := cg.nodes[caller]
	c.Callees.Add(callee)
	cg.nodes[caller] = c

	c = cg.nodes[callee]
	c.Callers.Add(caller)
	cg.nodes[callee] = c

	cg.roots.Remove(callee)
	cg.leaves.Remove(caller)
}

func (cg *CallGraph) AddNode(node GraphNode) {
	name := node.Name

	cg.nodes[name] = node
	cg.roots.Add(name)
	cg.leaves.Add(name)
}

func (cg *CallGraph) CollectNodes(root string,
	selector func(GraphNode) strset, depth int) strset {

	nodes := make(strset)
	nodes.Add(root)

	if depth == 0 {
		return nodes
	}

	for id := range selector(cg.nodes[root]) {
		nodes.Add(id)

		children := cg.CollectNodes(id, selector, depth-1)
		nodes = nodes.Union(children)
	}

	return nodes
}

//
// Save a CallGraph to an os.File using a binary encoding.
//
func (cg *CallGraph) Save(f *os.File) error {
	enc := gob.NewEncoder(f)

	if err := enc.Encode(cg.nodes); err != nil {
		return err
	}

	if err := enc.Encode(cg.roots); err != nil {
		return err
	}

	if err := enc.Encode(cg.leaves); err != nil {
		return err
	}

	if err := enc.Encode(cg.calls); err != nil {
		return err
	}

	return nil
}

//
// Simplify a CallGraph by collapsing call chains and dropping any
// unreferenced calls.
//
func (cg *CallGraph) Simplify() {
}

//
// Report the size of the graph (number of nodes and number of edges).
//
func (cg CallGraph) Size() (int, int) {
	return len(cg.nodes), len(cg.calls)
}

//
// Add intersecting nodes to this graph, where the call traces leading to
// any two leaf nodes must intersect within `depth` calls.
//
func (cg *CallGraph) AddIntersecting(g CallGraph, depth int) error {

	// Collect our leaves and their ancestors (up to `depth` calls).
	ancestors := make(strset)
	getCallers := func(n GraphNode) strset { return n.Callers }

	for id := range cg.leaves {
		ancestors = ancestors.Union(
			cg.CollectNodes(id, getCallers, depth))
	}

	// Keep those leaves with an ancestor common to the above.
	keep := make(strset)

	for leaf := range g.leaves {
		nodes := g.CollectNodes(leaf, getCallers, depth)
		for a := range nodes {
			if ancestors.Contains(a) {
				keep = keep.Union(nodes)
				break
			}
		}
	}

	for id := range keep {
		cg.AddNode(g.nodes[id])
	}

	for call, weight := range g.calls {
		if keep.Contains(call.Caller) && keep.Contains(call.Callee) {
			cg.AddCall(call.Caller, call.Callee)
			cg.calls[call] += (weight - 1)
		}
	}

	return nil
}

//
// Compute the intersection of two CallGraphs, where the call traces leading to
// any two leaf nodes must intersect within `depth` calls.
//
// If `keepBacktrace` is true, in addition to the intersecting nodes, the new
// graph will also contain the full backtrace from each node to its root.
//
func (cg CallGraph) Intersect(g CallGraph, depth int,
	keepBacktrace bool) (CallGraph, error) {

	result := NewCallGraph()

	// Collect our leaves and their ancestors (up to `depth` calls).
	ancestors := make(strset)
	getCallers := func(n GraphNode) strset { return n.Callers }

	for id := range cg.leaves {
		ancestors = ancestors.Union(
			cg.CollectNodes(id, getCallers, depth))
	}

	// Keep those leaves with an ancestor common to the above.
	keep := make(strset)

	for leaf := range g.leaves {
		nodes := g.CollectNodes(leaf, getCallers, depth)
		for a := range nodes {
			if ancestors.Contains(a) {
				keep = keep.Union(nodes)

				if keepBacktrace {
					backtrace := g.CollectNodes(leaf,
						getCallers, -1)

					keep = keep.Union(backtrace)
				}

				break
			}
		}
	}

	for id := range keep {
		result.AddNode(g.nodes[id])
	}

	for call, weight := range g.calls {
		if keep.Contains(call.Caller) && keep.Contains(call.Callee) {
			result.AddCall(call.Caller, call.Callee)
			result.calls[call] += (weight - 1)
		}
	}

	// Also filter out leaves from the LHS.
	ancestors = keep
	keep = make(strset)

	for leaf := range cg.leaves {
		nodes := cg.CollectNodes(leaf, getCallers, depth)
		for a := range nodes {
			if ancestors.Contains(a) {
				keep = keep.Union(nodes)

				if keepBacktrace {
					backtrace := cg.CollectNodes(leaf,
						getCallers, -1)

					keep = keep.Union(backtrace)
				}

				break
			}
		}
	}

	for id := range keep {
		result.AddNode(cg.nodes[id])
	}

	for call, weight := range cg.calls {
		if keep.Contains(call.Caller) && keep.Contains(call.Callee) {
			result.AddCall(call.Caller, call.Callee)
			result.calls[call] += (weight - 1)
		}
	}

	return result, nil
}

//
// Compute the union of two CallGraphs.
//
func (cg *CallGraph) Union(g CallGraph) error {
	for id, node := range g.nodes {
		// If we already have a GraphNode with this identifier,
		// merge the two descriptions and tag sets.
		if n, have := cg.nodes[id]; have {
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

			cg.nodes[id] = node
		} else {
			cg.AddNode(node)
		}
	}

	for call, count := range g.calls {
		cg.AddCall(call.Caller, call.Callee)
		cg.calls[call] += (count - 1)
	}

	return nil
}

func (cg CallGraph) WriteDot(out io.Writer) {
	fmt.Fprintln(out, `digraph {

	node [ fontname = "Inconsolata" ];
	edge [ fontname = "Avenir" ];

	labeljust = "l";
	labelloc = "b";
	rankdir = "BT";

`)

	for _, n := range cg.nodes {
		fmt.Fprintf(out, "	%s\n", n.Dot())
	}

	for c, count := range cg.calls {
		fmt.Fprintf(out, "	%s\n", c.Dot(cg, count))
	}

	fmt.Fprintf(out, "}\n")
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

	Callees strset
	Callers strset

	Tags strset
}

func newGraphNode(name string) GraphNode {
	var node GraphNode
	node.Name = name
	node.Callees = make(strset)
	node.Callers = make(strset)
	node.Tags = make(strset)

	return node
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

type Call struct {
	// Identifier of the caller.
	Caller string

	// Identifier of the callee.
	Callee string
}

// Output GraphViz for a Call.
func (c Call) Dot(graph CallGraph, weight int) string {
	caller := graph.nodes[c.Caller]
	callee := graph.nodes[c.Callee]

	attrs := map[string]interface{}{
		"label":    callee.Location.String(),
		"penwidth": 1 + math.Log(float64(weight)),
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

type nodeMaker func(CallSite) GraphNode

//
// Construct a callgraph from SOAAP's vulnerability analysis.
//
func VulnGraph(results Results, progress func(string)) CallGraph {
	graph := NewCallGraph()

	for _, v := range results.Vulnerabilities {
		trace := results.Traces[v.Trace]

		fn := func(cs CallSite) GraphNode {
			node := newGraphNode(cs.String() + v.Sandbox)
			node.Name = cs.String() + v.Sandbox
			node.Description = cs.Function
			if v.Sandbox != "" {
				node.Description += "\\n<<" + v.Sandbox + ">>"
			}

			node.Location = cs.Location
			node.Sandbox = v.Sandbox

			return node
		}

		top := fn(v.CallSite)
		top.CVE = v.CVE
		graph.AddNode(top)

		graph.Union(trace.graph(top, results.Traces, fn))
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
	chunk := int(math.Pow(10, math.Ceil(math.Log10(float64(total)/20))))
	if chunk < 1000 {
		chunk = 1000
	}

	go progress(fmt.Sprintf("Processing %d private accesses", total))

	count := 0
	for _, a := range accesses {
		trace := results.Traces[a.Trace]

		fn := func(cs CallSite) GraphNode {
			sandboxes := strings.Join(a.Sandboxes, ",")

			node := newGraphNode(cs.String() + sandboxes)
			node.Description = cs.Function
			if sandboxes != "" {
				node.Description += "\\n<<" + sandboxes + ">>"
			}

			node.Location = cs.Location

			return node
		}

		top := fn(a.CallSite)
		top.Owners = a.Sandboxes
		graph.AddNode(top)

		graph.Union(trace.graph(top, results.Traces, fn))

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
// Graph a single CallTrace, using a nodeMaker function to convert
// CallSite instances into graph nodes with identifiers, tags, etc.,
// appropriate to the analysis we're performing.
//
func (t CallTrace) graph(top GraphNode, traces []CallTrace, nm nodeMaker) CallGraph {
	graph := NewCallGraph()
	graph.AddNode(top)
	callee := top.Name

	t.Foreach(traces, func(cs CallSite) {
		node := nm(cs)
		graph.AddNode(node)

		caller := node.Name
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
