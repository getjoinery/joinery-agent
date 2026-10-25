package primitives

import "testing"

// data_root_provider_layer is an operate machine word that runs the data root
// script's provider-layer with enabled or disabled, and nothing else
// (specs/site_copy_final_test.md E2, B114).
func TestDataRootProviderLayerTakesOnlyEnabledOrDisabled(t *testing.T) {
	p, ok := Lookup("data_root_provider_layer")
	if !ok {
		t.Fatal("data_root_provider_layer should be registered")
	}
	if p.Class != ClassOperate || !p.Machine || p.Quiet != QuietAny {
		t.Errorf("data_root_provider_layer is an operate machine word that runs on a quiet site too, got %q machine=%v quiet=%v", p.Class, p.Machine, p.Quiet)
	}
	if p.Script == nil || p.Script.ScriptPath != "maintenance_scripts/install_tools/joinery_data_root.sh" {
		t.Fatalf("data_root_provider_layer runs joinery_data_root.sh, got %+v", p.Script)
	}
	if len(p.Script.Args) != 2 || p.Script.Args[0] != "provider-layer" || p.Script.Args[1] != "{layer}" {
		t.Errorf("data_root_provider_layer runs provider-layer {layer}, got %v", p.Script.Args)
	}
	for _, v := range []string{"enabled", "disabled"} {
		if _, err := Validate(p.Params, map[string]interface{}{"layer": v}); err != nil {
			t.Errorf("layer %q should be taken: %v", v, err)
		}
	}
	for _, v := range []interface{}{"unknown", "", "enabled ", "--keep-provider-layer", "enabled;x", 1, nil} {
		if _, err := Validate(p.Params, map[string]interface{}{"layer": v}); err == nil {
			t.Errorf("layer %v should be refused", v)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{}); err == nil {
		t.Error("the layer is required")
	}
	if _, err := Validate(p.Params, map[string]interface{}{"layer": "enabled", "path": "/etc"}); err == nil {
		t.Error("no other parameter is taken")
	}
}
