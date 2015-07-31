package soaap

import (
	"fmt"
	"strings"
)

//
// A string set is a map from a string to an empty interface.
//
// It's a bit silly that Go doesn't have a built-in set type. It's truly
// absurd that Go doesn't support the polymorphism that would let us implement
// such a type properly (i.e., not have to implement "intset", "strset", etc.).
//
type strset map[string]interface{}

// Put an element into the set, whether or not it's already there.
func (s *strset) Add(key string) {
	(*s)[key] = true
}

// Does this set contain a given element?
func (s strset) Contains(key string) bool {
	_, ok := s[key]
	return ok
}

// Join all of the strings in this set together.
func (s strset) Join(join string) string {
	return strings.Join(s.Values(), join)
}

// Remove a string from a set and report whether or not it was actually there.
func (s *strset) Remove(key string) bool {
	_, ok := (*s)[key]
	delete(*s, key)
	return ok
}

// Compute the intersection of two sets, generating a third set without
// modifying either of the input sets.
func (s strset) Intersection(other strset) strset {
	result := make(strset)

	for k := range s {
		_, ok := other[k]
		if ok {
			result[k] = true
		}
	}

	return result
}

// Transform each key in the set according to a fmt.Sprintf format.
func (s strset) TransformEach(format string) strset {
	result := strset{}

	for key := range s {
		result.Add(fmt.Sprintf(format, key))
	}

	return result
}

// Compute the union of two sets, generating a third set without modifying
// either of the input sets.
func (s strset) Union(other strset) strset {
	result := s

	for k := range other {
		result[k] = true
	}

	return result
}

// Extract all values contained in the set.
func (s strset) Values() []string {
	keys := make([]string, 0)

	for key := range s {
		keys = append(keys, key)
	}

	return keys
}
