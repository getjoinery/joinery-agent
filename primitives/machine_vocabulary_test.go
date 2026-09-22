package primitives

import (
	"reflect"
	"testing"
)

// pinnedMachineWords is every word a machine with no site of its own reports,
// written out by hand for the same reason pinnedVocabulary is: the set the
// plane may dispatch to the Docker host cannot change without a human editing
// this file. A word joins only when it asks or changes the machine and its
// script, if any, is one the support bundle carries
// (SupportBundlePublisher::$contents on the plane).
var pinnedMachineWords = []string{
	"agent_report",
	"check_status",
	"decommission_site",
	"disk_usage",
	"host_converge",
	"host_report",
	"install_report",
	"provision_certificate",
	"reset_failed_unit",
	"restart_agent",
	"unit_journal",
}

func TestASitelessMachineReportsOnlyMachineWords(t *testing.T) {
	for _, env := range []*ExecEnv{nil, {}, {ToolRoot: "/opt/joinery-agent/tree"}} {
		if got := RunnableNames(env); !reflect.DeepEqual(got, pinnedMachineWords) {
			t.Fatalf("siteless vocabulary drifted from the pin:\n got  %v\n want %v", got, pinnedMachineWords)
		}
	}
}

func TestAMachineWithASiteReportsEveryWord(t *testing.T) {
	if got, want := RunnableNames(&ExecEnv{SiteRoot: "/var/www/html/site"}), Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("a site's reported vocabulary must be the whole compiled list:\n got  %v\n want %v", got, want)
	}
}

// The words the Docker host refused in the fleet are the regression.
func TestTheWordsTheHostRefusedAreNotReportedThere(t *testing.T) {
	reported := map[string]bool{}
	for _, n := range RunnableNames(&ExecEnv{}) {
		reported[n] = true
	}
	for _, n := range []string{"agent_converge", "apply_update", "recovery_key_report"} {
		if reported[n] {
			t.Errorf("%s is reported by a machine with no site, which refuses it", n)
		}
	}
}
