package soaap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

//
// Parse a JSON file emitted by SOAAP.
//
// The `progress` callback will be notified when major events occur
// (top-level JSON parsing begins/ends, traces are parsed, etc.).
//
func ParseJSON(f *os.File, progress func(string)) (Results, error) {
	decoder := json.NewDecoder(f)
	var top map[string]map[string]json.RawMessage

	go progress(fmt.Sprintf("Loading %s", f.Name()))
	err := decoder.Decode(&top)
	if err != nil {
		return Results{}, err
	}
	raw := top["soaap"]

	var soaap Results

	maxTraceSize := len(raw)
	soaap.Traces = make([]CallTrace, maxTraceSize)

	parsed := 0

	// Once SOAAP issue #28 is resolved, we should be able to replace this
	// loop (as well as the `parseTrace` function) with a single call to
	// decoder.Decode().
	for k, v := range raw {
		switch k {
		case "access_origin_warning":
			// TODO

		case "cap_rights_warning":
			// TODO

		case "classified_warning":
			// TODO

		case "global_access_warning":
			// TODO

		case "global_lost_update":
			// TODO

		case "private_access":
			json.Unmarshal(v, &soaap.PrivateAccess)
			for i, vuln := range soaap.PrivateAccess {
				num, err := traceNumber(vuln.TraceName)
				if err != nil {
					return Results{}, err
				}

				soaap.PrivateAccess[i].Trace = num

				// Build a slice of *useful* sources (i.e., those with traces)
				sources := make([]DataSource, 0)

				for _, source := range vuln.Sources {
					if source.TraceRef != "" {
						num, err := traceNumber(source.TraceRef)
						if err != nil {
							return Results{}, err
						}
						source.Trace = num
						sources = append(sources, source)
					}
				}

				soaap.PrivateAccess[i].Sources = sources
			}

		case "private_leak":
			// TODO

		case "privileged_call":
			// TODO

		case "sandboxed_func":
			// TODO

		case "syscall_warning":
			// TODO

		case "vulnerability_warning":
			json.Unmarshal(v, &soaap.Vulnerabilities)
			for i, vuln := range soaap.Vulnerabilities {
				num, err := traceNumber(vuln.TraceName)
				if err != nil {
					return Results{}, err
				}

				soaap.Vulnerabilities[i].Trace = num
			}

		default:
			index, err := traceNumber(k)
			if err != nil {
				return soaap, errors.New(k + " is not a trace")
			}

			err = parseTrace(v, soaap.Traces, index)
			if err != nil {
				return soaap, err
			}
		}

		parsed += 1
		if parsed%10000 == 0 {
			go progress(fmt.Sprintf("Parsed %d traces", parsed))
		}
	}

	progress(fmt.Sprintf("Finished parsing %s.", f.Name()))

	return soaap, nil
}

//
// Unwrap the SOAAP encoding of a call trace.
//
// This should be simplified once SOAAP issue #28 is addressed: we won't
// need this function any more.
//
func parseTrace(j json.RawMessage, traces []CallTrace, index int) error {
	if index >= len(traces) {
		return fmt.Errorf("index (%d) too large for traces (len: %d)",
			index, len(traces))
	}

	var x map[string]json.RawMessage
	err := json.Unmarshal(j, &x)
	if err != nil {
		return err
	}

	var rawCallSites []json.RawMessage
	err = json.Unmarshal(x["trace"], &rawCallSites)
	if err != nil {
		return err
	}

	// The elements in a SOAAP call trace include at least n-1 functions:
	// the final element may be a reference to another trace.
	count := len(rawCallSites)

	t := &traces[index]
	t.CallSites = make([]CallSite, 0, count)
	t.Next = -1

	for i, v := range rawCallSites {
		var tmp CallSite
		err = json.Unmarshal(v, &tmp)
		if err != nil {
			return err
		}

		// If we managed to parse a real function name, this is
		// a CallSite and not a reference to a sub-trace.
		if tmp.Function != "" {
			t.CallSites = append(t.CallSites, tmp)
		} else {
			if i != count-1 {
				return fmt.Errorf("unable to convert call site %s", v)
			}

			var tmp map[string]string
			err = json.Unmarshal(v, &tmp)
			if err != nil {
				return err
			}

			ref, err := traceNumber(tmp["trace_ref"])
			if err != nil {
				return err
			}

			if ref > len(traces) {
				return errors.New(
					fmt.Sprintf("trace %d references %d "+
						" but we only have %d traces",
						index, ref, len(traces)))
			}
			t.Next = ref
		}
	}

	return err
}

// Extract a trace number from a string like '!trace42'.
func traceNumber(name string) (int, error) {
	if !strings.HasPrefix(name, "!trace") {
		return -1, errors.New("'" + name + "' is not a trace name")
	}

	i, err := strconv.ParseInt(name[6:], 10, 32)
	return int(i), err
}
