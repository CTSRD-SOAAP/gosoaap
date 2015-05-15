package soaap

import "fmt"
import "strings"

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
// Construct a callgraph from SOAAP's vulnerability analysis.
//
func VulnGraph(results Results) (map[string]GraphNode, []Call) {
	nodes := make(map[string]GraphNode)
	calls := make([]Call, 0, 1000)

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
			nodes[key] = n

			caller := key

			if callee != "" {
				call := Call{caller, callee}
				calls = append(calls, call)
			}

			callee = caller
		})
	}

	return nodes, calls
}

//
// Construct a callgraph of sandbox-private data accesses outside of sandboxes.
//
func PrivAccessGraph(results Results) (map[string]GraphNode, []Call) {
	nodes := make(map[string]GraphNode)
	calls := make([]Call, 0, 1000)

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
			nodes[key] = n

			caller := key

			if callee != "" {
				call := Call{caller, callee}
				calls = append(calls, call)
			}

			callee = caller
		})
	}

	return nodes, calls
}
