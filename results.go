package soaap

import (
	"encoding/gob"
	"fmt"
	"os"
	"strings"
)

//
// The results of running SOAAP on an application.
//
// The fields of this structure represent different analyses that SOAAP
// performs, as well as the complete graph of function calls that are referenced
// from these analyses.
//
type Results struct {
	Vulnerabilities []Vuln       `json:"vulnerability_warning"`
	PrivateAccess   []PrivAccess `json:"private_access"`
	Traces          []CallTrace  `json:"traces"`
}

//
// Load SOAAP results from an os.File (either binary- or JSON-encoded).
//
func LoadResults(f *os.File, report func(string)) (Results, error) {
	if strings.HasSuffix(f.Name(), ".gob") {
		var results Results
		err := gob.NewDecoder(f).Decode(&results)

		return results, err
	}

	return ParseJSON(f, report)
}

func (r Results) ExtractGraph(analysis string, progress func(string)) (CallGraph, error) {
	fn, ok := graphExtractors[analysis]
	if !ok {
		return CallGraph{},
			fmt.Errorf("unknown analysis: '%s'", analysis)
	}

	return fn(r, progress)
}

func (r Results) Save(f *os.File) error {
	return gob.NewEncoder(f).Encode(r)
}

//
// Information that SOAAP reports about a vulnerability.
//
type Vuln struct {
	CallSite

	Sandbox    string
	Type       string
	CVE        []CVE
	Restricted bool `json:"restricted_rights"`
}

func (v Vuln) CVEs() strset {
	cves := strset{}

	for _, c := range v.CVE {
		cves.Add(c.String())
	}

	return cves
}

type CVE struct {
	ID string
}

func (c CVE) String() string {
	return c.ID
}

//
// Information SOAAP reports about access to sandbox-private data
// outside of the sandbox.
//
type PrivAccess struct {
	CallSite

	Sandboxes []SandboxName `json:"sandbox_private"`
	Sources   []DataSource
}

func (p PrivAccess) DataOwners() strset {
	sandboxes := strset{}

	for _, s := range p.Sandboxes {
		sandboxes.Add(s.Name)
	}

	return sandboxes
}

type SandboxName struct {
	Name string
}

type DataSource struct {
	Location SourceLocation
	Trace    int
	TraceRef string `json:"trace_ref"`
}

//
// A single call trace, from a warning location to the root function.
//
// Common elements of multiple traces may be refactored into separate
// traces: if this trace has a predecessor, it is identified by `Next`.
//
type CallTrace struct {
	CallSites []CallSite
	Next      int
}

//
// Apply a function to every CallSite in a trace, starting at the SOAAP
// warning location and moving to the root, passing through other traces
// contained in `traces` as necessary.
//
// Example:
// ```go
// trace.Foreach(traces, func(cs CallSite) { fmt.Println(cs.Function) })
// ```
//
func (t CallTrace) Foreach(traces []CallTrace, fn func(CallSite)) error {
	for _, cs := range t.CallSites {
		if cs.Location.File != "" {
			fn(cs)
		}
	}

	if t.Next >= 0 {
		if t.Next >= len(traces) {
			return fmt.Errorf("trace ID (%d) out of range (have %d traces)",
				t.Next, len(traces))
		}

		traces[t.Next].Foreach(traces, fn)
	}

	return nil
}

//
// A node in the call graph.
//
// This is a location of either a SOAAP warning or else a call to another
// function in a warning's call stack.
//
type CallSite struct {
	Function  string
	Location  SourceLocation
	Trace     int
	TraceName string `json:"trace_ref"`
}

func (c CallSite) String() string {
	return fmt.Sprintf("%s: %s", c.Function, c.Location)
}

//
// A location in source code.
//
type SourceLocation struct {
	File    string
	Line    int
	Library string
}

func (l SourceLocation) String() string {
	if l.Line == 0 {
		return ""
	}

	return fmt.Sprintf("%s:%d (%s)", l.File, l.Line, l.Library)
}
