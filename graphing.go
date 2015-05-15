package soaap

import "fmt"
import "errors"
import "strings"

type CallGraph struct {
	Nodes map[string]GraphNode
	Calls []Call
}

func NewCallGraph() CallGraph {
	return CallGraph{
		make(map[string]GraphNode),
		make([]Call, 0, 1000),
	}
}

func (cg *CallGraph) AddCall(caller string, callee string) {
	cg.Calls = append(cg.Calls, Call{caller, callee})
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

type Call struct {
	// Identifier of the caller.
	Caller string

	// Identifier of the callee.
	Callee string
}

//
// A function that extracts a CallGraph from SOAAP Results.
//
type graphFn func(results Results) CallGraph

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

//
// Construct a callgraph from SOAAP's vulnerability analysis.
//
func VulnGraph(results Results) CallGraph {
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

		var callee string

		trace.Foreach(results.Traces, func(cs CallSite) {
			key, n := fn(cs)
			graph.Nodes[key] = n

			caller := key

			if callee != "" {
				graph.AddCall(caller, callee)
			}

			callee = caller
		})
	}

	return graph
}

//
// Construct a callgraph of sandbox-private data accesses outside of sandboxes.
//
func PrivAccessGraph(results Results) CallGraph {
	graph := NewCallGraph()

	for _, a := range results.PrivateAccess {
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

		var callee string

		trace.Foreach(results.Traces, func(cs CallSite) {
			key, n := fn(cs)
			graph.Nodes[key] = n

			caller := key

			if callee != "" {
				graph.AddCall(caller, callee)
			}

			callee = caller
		})
	}

	return graph
}
