package primitives

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// MaxParamsBytes bounds the whole params object of a single job. The plane
// applies the same ceiling when it BUILDS the job, so a job this node would
// refuse for size fails loudly at build time instead of travelling here to die
// (never-silently, the rule A4 was decided under).
const MaxParamsBytes = 16 * 1024

// ParamType is the complete set of shapes a parameter may have. There is no
// "any" and no "raw" — every value that reaches a primitive has been through a
// declared type. Notably absent: anything that could carry a command.
//
// ParamMap is the one composite, added for stage_chain, and it is bounded in
// four directions rather than one: the number of entries, the length of each
// key, the length of each value, and the encoded size of the whole. Its values
// are strings and only strings — there is no nesting, so "a map" cannot become
// "an object with a field somebody later reads as a path".
type ParamType string

const (
	ParamString ParamType = "string"
	ParamInt    ParamType = "int"
	ParamBool   ParamType = "bool"
	ParamEnum   ParamType = "enum"
	ParamMap    ParamType = "map"
)

var paramTypeAllowed = map[ParamType]bool{
	ParamString: true,
	ParamInt:    true,
	ParamBool:   true,
	ParamEnum:   true,
	ParamMap:    true,
}

// ParamSpec declares one parameter and its bounds. A spec with no bounds is
// still bounded: strings get DefaultMaxLen, ints get the int64 range clamped by
// Min/Max when set.
type ParamSpec struct {
	Name     string
	Type     ParamType
	Required bool

	// MaxLen bounds a string. Zero means DefaultMaxLen.
	MaxLen int
	// Pattern, when set, a string must match it entirely.
	Pattern *regexp.Regexp
	// Min / Max bound an int. Both zero means "any int64".
	Min, Max int64
	// Values enumerates the accepted strings for ParamEnum.
	Values []string

	// KeyPattern bounds a ParamMap's keys; Pattern bounds its values. Both are
	// required on a map, so a map parameter cannot be declared without saying
	// what may be in it.
	KeyPattern *regexp.Regexp
	// MaxEntries caps a ParamMap's size in entries. Required on a map: the
	// byte ceiling alone would allow thousands of tiny entries.
	MaxEntries int
	// MaxKeyLen bounds one key of a ParamMap. Zero means DefaultMaxLen.
	MaxKeyLen int
}

// DefaultMaxLen is the ceiling on any string parameter that does not set one.
const DefaultMaxLen = 512

// Params is a validated parameter set. It can only be produced by Validate, so
// a primitive's Run function cannot be handed unvalidated wire data.
type Params struct {
	values map[string]interface{}
}

// String returns a validated string parameter (empty when absent).
func (p Params) String(name string) string {
	if v, ok := p.values[name].(string); ok {
		return v
	}
	return ""
}

// Int returns a validated int parameter (zero when absent).
func (p Params) Int(name string) int64 {
	if v, ok := p.values[name].(int64); ok {
		return v
	}
	return 0
}

// Bool returns a validated bool parameter (false when absent).
func (p Params) Bool(name string) bool {
	if v, ok := p.values[name].(bool); ok {
		return v
	}
	return false
}

// Map returns a validated map parameter (nil when absent). The returned map is
// the validated copy, not the wire object.
func (p Params) Map(name string) map[string]string {
	if v, ok := p.values[name].(map[string]string); ok {
		return v
	}
	return nil
}

// Has reports whether the job supplied this parameter at all.
func (p Params) Has(name string) bool {
	_, ok := p.values[name]
	return ok
}

var paramNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// validateSpecs checks a primitive's declaration at registration time.
func validateSpecs(specs []ParamSpec) error {
	seen := map[string]bool{}
	for _, s := range specs {
		if !paramNamePattern.MatchString(s.Name) {
			return fmt.Errorf("invalid parameter name %q", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate parameter %q", s.Name)
		}
		seen[s.Name] = true
		if !paramTypeAllowed[s.Type] {
			return fmt.Errorf("parameter %q has unknown type %q", s.Name, s.Type)
		}
		if s.Type == ParamEnum && len(s.Values) == 0 {
			return fmt.Errorf("enum parameter %q declares no values", s.Name)
		}
		if s.Type != ParamEnum && len(s.Values) > 0 {
			return fmt.Errorf("parameter %q declares values but is not an enum", s.Name)
		}
		if s.Min > s.Max && s.Max != 0 {
			return fmt.Errorf("parameter %q has Min above Max", s.Name)
		}
		if s.Type == ParamMap {
			if s.KeyPattern == nil || s.Pattern == nil {
				return fmt.Errorf("map parameter %q must bound both its keys and its values", s.Name)
			}
			if s.MaxEntries <= 0 {
				return fmt.Errorf("map parameter %q declares no entry limit", s.Name)
			}
		}
		if s.Type != ParamMap && (s.KeyPattern != nil || s.MaxEntries != 0 || s.MaxKeyLen != 0) {
			return fmt.Errorf("parameter %q declares map bounds but is not a map", s.Name)
		}
	}
	return nil
}

// Validate checks a wire-supplied parameter object against a primitive's
// declared specs and returns the validated set.
//
// Unknown keys are refused rather than dropped. A dropped key is a parameter
// the sender believes is in effect and the node has silently ignored, which is
// the shape of every "it looked like it worked" failure this architecture
// exists to remove.
func Validate(specs []ParamSpec, raw map[string]interface{}) (Params, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}

	// Size first: bound the object before walking it.
	if encoded, err := json.Marshal(raw); err != nil {
		return Params{}, refusedf("params are not encodable: %v", err)
	} else if len(encoded) > MaxParamsBytes {
		return Params{}, refusedf("params are %d bytes, over the %d-byte limit", len(encoded), MaxParamsBytes)
	}

	declared := map[string]ParamSpec{}
	for _, s := range specs {
		declared[s.Name] = s
	}

	var unknown []string
	for key := range raw {
		if _, ok := declared[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Params{}, refusedf("params carry undeclared key(s): %s", strings.Join(unknown, ", "))
	}

	out := map[string]interface{}{}
	for _, s := range specs {
		value, present := raw[s.Name]
		if !present || value == nil {
			if s.Required {
				return Params{}, refusedf("param %q is required", s.Name)
			}
			continue
		}
		coerced, err := coerce(s, value)
		if err != nil {
			return Params{}, err
		}
		out[s.Name] = coerced
	}

	return Params{values: out}, nil
}

func coerce(s ParamSpec, value interface{}) (interface{}, error) {
	switch s.Type {
	case ParamString, ParamEnum:
		str, ok := value.(string)
		if !ok {
			return nil, refusedf("param %q must be a string", s.Name)
		}
		max := s.MaxLen
		if max <= 0 {
			max = DefaultMaxLen
		}
		if len(str) > max {
			return nil, refusedf("param %q is %d bytes, over its %d-byte limit", s.Name, len(str), max)
		}
		if s.Type == ParamEnum {
			for _, allowed := range s.Values {
				if str == allowed {
					return str, nil
				}
			}
			return nil, refusedf("param %q is not one of the accepted values", s.Name)
		}
		if s.Pattern != nil && !s.Pattern.MatchString(str) {
			return nil, refusedf("param %q does not match its accepted form", s.Name)
		}
		return str, nil

	case ParamInt:
		// JSON numbers arrive as float64 through encoding/json.
		var n int64
		switch v := value.(type) {
		case float64:
			if v != math.Trunc(v) || math.IsInf(v, 0) || math.IsNaN(v) {
				return nil, refusedf("param %q must be a whole number", s.Name)
			}
			if v > math.MaxInt64 || v < math.MinInt64 {
				return nil, refusedf("param %q is out of range", s.Name)
			}
			n = int64(v)
		case int64:
			n = v
		case int:
			n = int64(v)
		default:
			return nil, refusedf("param %q must be a number", s.Name)
		}
		if s.Min != 0 || s.Max != 0 {
			if n < s.Min || n > s.Max {
				return nil, refusedf("param %q must be between %d and %d", s.Name, s.Min, s.Max)
			}
		}
		return n, nil

	case ParamBool:
		b, ok := value.(bool)
		if !ok {
			return nil, refusedf("param %q must be true or false", s.Name)
		}
		return b, nil

	case ParamMap:
		raw, ok := value.(map[string]interface{})
		if !ok {
			return nil, refusedf("param %q must be an object", s.Name)
		}
		if len(raw) > s.MaxEntries {
			return nil, refusedf("param %q has %d entries, over its limit of %d",
				s.Name, len(raw), s.MaxEntries)
		}
		maxKey := s.MaxKeyLen
		if maxKey <= 0 {
			maxKey = DefaultMaxLen
		}
		maxVal := s.MaxLen
		if maxVal <= 0 {
			maxVal = DefaultMaxLen
		}
		out := make(map[string]string, len(raw))
		// Sorted, so a refusal names the same offending entry every time
		// rather than whichever one the map iteration reached first — a
		// message that changes between identical runs is a message nobody
		// trusts.
		keys := make([]string, 0, len(raw))
		for k := range raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(k) > maxKey || !s.KeyPattern.MatchString(k) {
				return nil, refusedf("param %q has an entry named %q, which is not an accepted name", s.Name, k)
			}
			str, ok := raw[k].(string)
			if !ok {
				return nil, refusedf("param %q entry %q must be a string", s.Name, k)
			}
			if len(str) > maxVal {
				return nil, refusedf("param %q entry %q is %d bytes, over its %d-byte limit",
					s.Name, k, len(str), maxVal)
			}
			if !s.Pattern.MatchString(str) {
				return nil, refusedf("param %q entry %q does not match its accepted form", s.Name, k)
			}
			out[k] = str
		}
		return out, nil
	}
	return nil, refusedf("param %q has an unsupported type", s.Name)
}
