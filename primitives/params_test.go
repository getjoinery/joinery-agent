package primitives

import (
	"regexp"
	"strings"
	"testing"
)

func TestUndeclaredParamsAreRefusedNotDropped(t *testing.T) {
	specs := []ParamSpec{{Name: "keep", Type: ParamInt, Min: 1, Max: 10}}
	_, err := Validate(specs, map[string]interface{}{"keep": float64(3), "recovery_public_key": "age1..."})
	if !Refused(err) {
		t.Fatalf("an undeclared parameter must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "recovery_public_key") {
		t.Errorf("the refusal must name the offending key so the plane can be fixed; got %q", err)
	}
}

// §3.5.1 / A4: a job carrying key material is refused as out-of-vocabulary like
// any other wire-supplied instruction. That falls out of the rule above, and is
// asserted here because it is the specific thing the rule exists to stop.
func TestWireSuppliedKeyMaterialIsRefused(t *testing.T) {
	specs := []ParamSpec{{Name: "profile", Type: ParamEnum, Values: []string{"manager", "site"}}}
	for _, key := range []string{"recovery_public_key", "encryption_key", "age_recipient"} {
		_, err := Validate(specs, map[string]interface{}{"profile": "manager", key: "whatever"})
		if !Refused(err) {
			t.Errorf("a job supplying %q must be refused; got %v", key, err)
		}
	}
}

func TestRequiredAndTypedParams(t *testing.T) {
	specs := []ParamSpec{
		{Name: "name", Type: ParamString, Required: true, MaxLen: 8},
		{Name: "count", Type: ParamInt, Min: 1, Max: 5},
		{Name: "force", Type: ParamBool},
		{Name: "mode", Type: ParamEnum, Values: []string{"fast", "full"}},
	}

	if _, err := Validate(specs, map[string]interface{}{}); !Refused(err) {
		t.Error("a missing required parameter must be refused")
	}
	if _, err := Validate(specs, map[string]interface{}{"name": "toolongforthis"}); !Refused(err) {
		t.Error("an over-length string must be refused")
	}
	if _, err := Validate(specs, map[string]interface{}{"name": "ok", "count": float64(9)}); !Refused(err) {
		t.Error("an out-of-range int must be refused")
	}
	if _, err := Validate(specs, map[string]interface{}{"name": "ok", "count": float64(2.5)}); !Refused(err) {
		t.Error("a fractional value for an int must be refused")
	}
	if _, err := Validate(specs, map[string]interface{}{"name": "ok", "force": "yes"}); !Refused(err) {
		t.Error("a string where a bool is declared must be refused, not coerced")
	}
	if _, err := Validate(specs, map[string]interface{}{"name": "ok", "mode": "delete"}); !Refused(err) {
		t.Error("a value outside an enum must be refused")
	}

	p, err := Validate(specs, map[string]interface{}{
		"name": "ok", "count": float64(3), "force": true, "mode": "full"})
	if err != nil {
		t.Fatalf("a well-formed parameter set must validate: %v", err)
	}
	if p.String("name") != "ok" || p.Int("count") != 3 || !p.Bool("force") || p.String("mode") != "full" {
		t.Errorf("validated values did not survive: %+v", p)
	}
	if p.Has("absent") {
		t.Error("Has must be false for a parameter the job never sent")
	}
}

func TestStringsAreBoundedEvenWithoutADeclaredLimit(t *testing.T) {
	specs := []ParamSpec{{Name: "note", Type: ParamString}}
	_, err := Validate(specs, map[string]interface{}{"note": strings.Repeat("x", DefaultMaxLen+1)})
	if !Refused(err) {
		t.Fatal("a string with no declared MaxLen must still be bounded by DefaultMaxLen")
	}
}

func TestPatternedStringRefusesAnythingElse(t *testing.T) {
	specs := []ParamSpec{{Name: "archive", Type: ParamString, Pattern: regexp.MustCompile(`^[A-Za-z0-9._-]+$`)}}
	for _, bad := range []string{"../../etc/passwd", "a b", "x;y", "$(id)"} {
		if _, err := Validate(specs, map[string]interface{}{"archive": bad}); !Refused(err) {
			t.Errorf("archive %q must be refused", bad)
		}
	}
	if _, err := Validate(specs, map[string]interface{}{"archive": "backup-1.tar.gz"}); err != nil {
		t.Errorf("a well-formed archive name must validate: %v", err)
	}
}

func TestParamsObjectIsSizeBounded(t *testing.T) {
	specs := []ParamSpec{{Name: "note", Type: ParamString, MaxLen: MaxParamsBytes * 2}}
	_, err := Validate(specs, map[string]interface{}{"note": strings.Repeat("y", MaxParamsBytes+1)})
	if !Refused(err) {
		t.Fatal("the whole params object must be bounded before any field is walked")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal should name the limit; got %q", err)
	}
}

func TestRegistrationRefusesABadVocabulary(t *testing.T) {
	cases := []struct {
		what string
		p    Primitive
	}{
		{"an unknown class", Primitive{Name: "bad_class", Class: Class("exec"), Run: noopRun}},
		{"a name that reads like a path", Primitive{Name: "../etc/passwd", Class: ClassObserve, Run: noopRun}},
		{"no implementation", Primitive{Name: "empty_one", Class: ClassObserve}},
		{"two implementations", Primitive{Name: "both_ways", Class: ClassObserve, Run: noopRun,
			Script: &ScriptSpec{Interpreter: "/bin/true", ScriptPath: "x"}}},
		{"a duplicate name", Primitive{Name: "check_status", Class: ClassObserve, Run: noopRun}},
		{"a parameter with an unknown type", Primitive{Name: "bad_param", Class: ClassObserve, Run: noopRun,
			Params: []ParamSpec{{Name: "x", Type: ParamType("raw")}}}},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("registering a primitive with %s must panic at startup, not be accepted", c.what)
				}
			}()
			Register(c.p)
		}()
	}
}
