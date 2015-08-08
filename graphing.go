package soaap

import (
	"encoding/gob"
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

	//
	// Reconstitute each node's callers and callees.
	//
	for call := range cg.calls {
		callee := cg.nodes[call.Callee]
		callee.CallsIn = append(callee.CallsIn, call)
		cg.nodes[call.Callee] = callee

		caller := cg.nodes[call.Caller]
		caller.CallsOut = append(caller.CallsOut, call)
		cg.nodes[call.Caller] = caller
	}

	return cg, nil
}

func (cg *CallGraph) AddCall(call Call) {
	cg.calls[call] += 1

	caller := call.Caller
	callee := call.Callee

	// This idiom (copy, modify, update) is terribly tedious, but
	// Go maps always return copies rather than references.
	c := cg.nodes[caller]
	UpdateCalls(&c.CallsOut, call)
	cg.nodes[caller] = c

	c = cg.nodes[callee]
	UpdateCalls(&c.CallsIn, call)
	cg.nodes[callee] = c

	cg.roots.Remove(callee)
	cg.leaves.Remove(caller)
}

func (cg *CallGraph) AddCalls(call Call, weight int) {
	cg.AddCall(call)
	cg.calls[call] += weight - 1
}

func (cg *CallGraph) AddNode(node GraphNode) {
	name := node.Name

	if n, ok := cg.nodes[name]; ok {
		node.Update(n)
	}

	cg.nodes[name] = node

	if len(node.CallsIn) == 0 {
		cg.roots.Add(name)
	}

	if len(node.CallsOut) == 0 {
		cg.leaves.Add(name)
	}
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
func (cg CallGraph) Save(f *os.File) error {
	enc := gob.NewEncoder(f)

	//
	// We don't want the gob encoder to flatten each node's Call pointers,
	// so make a copy of the nodes with no calls.
	//
	nodes := make(map[string]GraphNode)
	for name, node := range cg.nodes {
		n := node
		n.CallsOut = nil
		n.CallsIn = nil
		nodes[name] = n
	}

	if err := enc.Encode(nodes); err != nil {
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
func (cg CallGraph) Simplified() CallGraph {
	g := NewCallGraph()

	for r := range cg.roots {
		g.addSimplified(cg.nodes[r], cg)
	}

	return g
}

//
// Recursively add simplified call chains to a CallGraph
//
func (cg *CallGraph) addSimplified(begin GraphNode, old CallGraph) {
	cg.AddNode(begin)

	callChain := walkChain(begin, old.nodes)
	var next GraphNode

	if len(callChain) == 0 {
		next = begin

	} else {
		lastCall := callChain[len(callChain)-1]
		next = old.nodes[lastCall.Callee]
		cg.AddNode(next)

		if len(callChain) == 1 {
			cg.AddCall(lastCall)

		} else {
			call := Call{
				Caller:  begin.Name,
				Callee:  next.Name,
				Sandbox: lastCall.Sandbox,
			}

			weight := 0
			for _, call := range callChain {
				weight += old.calls[call]
			}

			cg.AddCalls(call, weight)
		}
	}

	for _, call := range next.CallsOut {
		cg.addSimplified(old.nodes[call.Callee], old)
		cg.AddCall(call)
	}
}

//
// Traverse a linear chain of calls until we encounter an "interesting" node
// (one with multiple callers, multiple callees or a CVE).
//
// Returns the number of calls traversed and the final node in the chain.
//
func walkChain(start GraphNode, nodes map[string]GraphNode) []Call {
	chain := make([]Call, 0)
	n := start

	for {
		if len(n.CallsIn) > 1 || len(n.CallsOut) != 1 || len(n.CVE) > 0 {
			return chain
		}

		var call Call
		for _, c := range n.CallsOut {
			call = c
		}

		next := nodes[call.Callee]

		if len(next.CVE) > 0 {
			return chain
		}

		chain = append(chain, call)
		n = next
	}

	return chain
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

	for id := range cg.leaves {
		ancestors = ancestors.Union(
			cg.CollectNodes(id, GraphNode.Callers, depth))
	}

	// Keep those leaves with an ancestor common to the above.
	keep := make(strset)

	for leaf := range g.leaves {
		nodes := g.CollectNodes(leaf, GraphNode.Callers, depth)
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
			cg.AddCalls(call, weight)
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

	for id := range cg.leaves {
		ancestors = ancestors.Union(
			cg.CollectNodes(id, GraphNode.Callers, depth))
	}

	// Keep those leaves with an ancestor common to the above.
	keep := make(strset)

	for leaf := range g.leaves {
		nodes := g.CollectNodes(leaf, GraphNode.Callers, depth)
		for a := range nodes {
			if ancestors.Contains(a) {
				keep = keep.Union(nodes)

				if keepBacktrace {
					backtrace := g.CollectNodes(leaf,
						GraphNode.Callers, -1)

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
			result.AddCall(call)
			result.calls[call] += (weight - 1)
		}
	}

	// Also filter out leaves from the LHS.
	ancestors = keep
	keep = make(strset)

	for leaf := range cg.leaves {
		nodes := cg.CollectNodes(leaf, GraphNode.Callers, depth)
		for a := range nodes {
			if ancestors.Contains(a) {
				keep = keep.Union(nodes)

				if keepBacktrace {
					backtrace := cg.CollectNodes(leaf,
						GraphNode.Callers, -1)

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
			result.AddCall(call)
			result.calls[call] += (weight - 1)
		}
	}

	return result, nil
}

//
// Compute the union of two CallGraphs.
//
func (cg *CallGraph) Union(g CallGraph) error {
	for _, node := range g.nodes {
		cg.AddNode(node)
	}

	for call, count := range g.calls {
		cg.AddCall(call)
		cg.calls[call] += (count - 1)
	}

	return nil
}

func (cg CallGraph) WriteDot(out io.Writer, groupBy string) error {
	fmt.Fprintln(out, `digraph {

	graph [ fontname = "Inconsolata" ];
	node [ fontname = "Inconsolata" ];
	edge [ fontname = "Avenir" ];

	labeljust = "l";
	labelloc = "b";
	rankdir = "BT";

`)

	ungrouped := make([]string, 0)

	if groupBy == "" {
		for name := range cg.nodes {
			ungrouped = append(ungrouped, name)
		}

	} else {
		nodeGroups := make(map[string][]string)

		for _, n := range cg.nodes {
			var groupName string

			switch groupBy {
			case "function":
				groupName = n.Function

			case "library":
				groupName = n.Library

			case "namespace":
				functionName := strings.Split(n.Function, "(")[0]

				components := strings.Split(functionName, "::")
				if len(components) <= 1 {
					groupName = ""
				} else {
					groupName = strings.Join(components[:len(components)-1], "::")
					n.Function = n.Function[len(groupName)+2:]
					cg.nodes[n.Name] = n
				}

			case "sandbox":
				groupName = n.Sandbox

			default:
				return fmt.Errorf("unknown grouping strategy '%s'", groupBy)
			}

			if groupName != "" {
				nodeGroups[groupName] = append(nodeGroups[groupName], n.Name)
			} else {
				ungrouped = append(ungrouped, n.Name)
			}
		}

		for name, nodes := range nodeGroups {
			fmt.Fprintf(out, "	subgraph \"cluster_%s\" {\n", name)
			fmt.Fprintf(out, "		graph [ bgcolor = \"#dddddd66\" ];\n")
			fmt.Fprintf(out, "		label = \"%s\";\n", name)

			for _, n := range nodes {
				fmt.Fprintf(out, "		%s\n", cg.nodes[n].Dot())
			}

			fmt.Fprintf(out, "	}\n\n")
		}
	}

	for _, n := range ungrouped {
		fmt.Fprintf(out, "	%s\n", cg.nodes[n].Dot())
	}

	for c, count := range cg.calls {
		fmt.Fprintf(out, "	%s\n", c.Dot(cg, count))
	}

	fmt.Fprintf(out, "}\n")

	return nil
}

//
// A node in a call graph.
//
// This is derived from a call site or other program location, but can have
// an arbitrary name and description appropriate to a particular analysis.
//
type GraphNode struct {
	Name string

	// The name of the function this node is in / represents.
	Function string

	// The library that the function is defined in.
	Library string

	// The sandbox that this code is being executed in.
	//
	// Note that SOAAP can discriminate among the same function executing
	// in different sandboxes.
	Sandbox string

	// A vulnerability (current or previous) is known at this location.
	CVE strset

	// The name of the sandbox(es) that own the data being accessed.
	Owners strset

	CallsIn  []Call
	CallsOut []Call

	Tags strset
}

func newGraphNode(cs CallSite, sandbox string) GraphNode {
	var node GraphNode
	node.Name = cs.Function + " : " + sandbox
	node.Function = cs.Function
	node.Library = cs.Location.Library
	node.Sandbox = sandbox
	node.CVE = make(strset)
	node.Owners = make(strset)
	node.CallsIn = make([]Call, 0)
	node.CallsOut = make([]Call, 0)
	node.Tags = make(strset)

	return node
}

func (n GraphNode) Callers() strset {
	callers := strset{}
	for _, call := range n.CallsIn {
		callers.Add(call.Caller)
	}
	return callers
}

//
// Construct a GraphViz Dot description of a GraphNode.
//
// This applies SOAAP-specific styling depending on a node's tags.
//
func (n GraphNode) Dot() string {
	label := n.Function

	// Trim long node names
	if len(label) > 30 {
		//
		// Split node name into <function>(<parameters>) - if applicable.
		// Some node names don't have parameters (e.g., those that c++filt
		// failed to demangle for some reason).
		//
		function := strings.Split(n.Function, "(")[0]

		if len(function) == len(n.Function) {
			// There are no parameters: perhaps demangling failed?
			label = n.Function[:30] + " [...]"

		} else {
			//
			parameters := n.Function[len(function)+1 : len(n.Function)-1]

			plen := 28 - len(function)
			if plen < 0 {
				plen = 0
			} else if plen > len(parameters) {
				plen = len(parameters)
			}
			parameters = parameters[:plen]

			label = fmt.Sprintf("%s(%s [...])", function, parameters)
		}
	}

	if len(n.CVE) > 0 {
		label += "\n" + n.CVE.TransformEach("[[%s]]").Join(" ")
	}

	if n.Sandbox != "" {
		label += "\n<<" + n.Sandbox + ">>"
	}

	attrs := map[string]interface{}{
		"label": label,
		"style": "filled",
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

func (n *GraphNode) Update(g GraphNode) {
	if n.Library == "" {
		n.Library = g.Library
	}

	UpdateCalls(&n.CallsIn, g.CallsIn...)
	UpdateCalls(&n.CallsOut, g.CallsOut...)
	n.CVE.Union(g.CVE)
	n.Owners.Union(g.Owners)
	n.Tags.Union(g.Tags)
}

func UpdateCalls(current *[]Call, calls ...Call) {
	// This is O(n x m), but n and m are typically very small...
	for _, c := range calls {
		alreadyHave := false

		for _, existing := range *current {
			if existing == c {
				alreadyHave = true
				break
			}
		}

		if !alreadyHave {
			*current = append(*current, c)
		}
	}
}

type Call struct {
	// Identifier of the caller.
	Caller string

	// Identifier of the callee.
	Callee string

	// Location of the call.
	CallSite SourceLocation

	// The name of the sandbox the call is occurring in
	// (or the empty string if unsandboxed).
	Sandbox string
}

// Output GraphViz for a Call.
func (c Call) Dot(graph CallGraph, weight int) string {
	caller := graph.nodes[c.Caller]
	callee := graph.nodes[c.Callee]

	label := c.CallSite.String()
	colour := "#993333"
	if c.Sandbox != "" {
		colour = "#339933"
	}

	attrs := map[string]interface{}{
		"color":     colour + "66",
		"fontcolor": colour,
		"label":     label,
		"penwidth":  1 + math.Log(float64(weight)),
		"weight":    weight,
	}

	return fmt.Sprintf("\"%s\" -> \"%s\" %s;\n",
		caller.Name, callee.Name, dotAttrs(attrs))
}

//
// A function that extracts a CallGraph from SOAAP Results.
//
type graphFn func(results Results, progress func(string)) (CallGraph, error)

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

type callMaker func(GraphNode, GraphNode, CallSite) Call
type nodeMaker func(CallSite) GraphNode

//
// Construct a callgraph from SOAAP's vulnerability analysis.
//
func VulnGraph(results Results, progress func(string)) (CallGraph, error) {
	graph := NewCallGraph()

	for _, v := range results.Vulnerabilities {
		trace := results.Traces[v.Trace]

		fn := func(cs CallSite) GraphNode {
			return newGraphNode(cs, v.Sandbox)
		}

		call := func(caller GraphNode, callee GraphNode,
			cs CallSite) Call {
			return Call{
				Caller:   caller.Name,
				Callee:   callee.Name,
				CallSite: cs.Location,
				Sandbox:  v.Sandbox,
			}
		}

		top := fn(v.CallSite)
		top.CVE = v.CVEs()
		graph.AddNode(top)

		g, err := trace.graph(top, results.Traces, fn, call)
		if err != nil {
			return CallGraph{}, err
		}

		graph.Union(g)
	}

	return graph, nil
}

//
// Construct a callgraph of sandbox-private data accesses outside of sandboxes.
//
func PrivAccessGraph(results Results, progress func(string)) (CallGraph, error) {
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
		sandboxes := a.DataOwners().Join(",")

		fn := func(cs CallSite) GraphNode {
			return newGraphNode(cs, sandboxes)
		}

		call := func(caller GraphNode, callee GraphNode, cs CallSite) Call {
			return Call{
				Caller:   caller.Name,
				Callee:   callee.Name,
				CallSite: cs.Location,
			}
		}

		top := fn(a.CallSite)
		top.Owners = a.DataOwners()
		graph.AddNode(top)

		g, err := trace.graph(top, results.Traces, fn, call)
		if err != nil {
			return CallGraph{}, err
		}

		graph.Union(g)

		count++
		if count%chunk == 0 {
			go progress(
				fmt.Sprintf("Processed %d/%d accesses",
					count, total))
		}
	}

	return graph, nil
}

//
// Graph a single CallTrace, using a nodeMaker function to convert
// CallSite instances into graph nodes with identifiers, tags, etc.,
// appropriate to the analysis we're performing.
//
func (t CallTrace) graph(top GraphNode, traces []CallTrace,
	makeNode nodeMaker, makeCall callMaker) (CallGraph, error) {
	graph := NewCallGraph()
	graph.AddNode(top)
	callee := top

	err := t.Foreach(traces, func(cs CallSite) {
		caller := makeNode(cs)
		graph.AddNode(caller)

		graph.AddCall(makeCall(caller, callee, cs))
		callee = caller
	})

	return graph, err
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
