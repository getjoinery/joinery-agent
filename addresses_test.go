package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The list is addresses only (the plane validates each as one), never a
// loopback or link-local one, IPv4 before IPv6, and bounded.
func TestMachineAddressesAreGlobalUnicastOnly(t *testing.T) {
	addrs := machineAddresses()
	if len(addrs) > maxReportedAddresses {
		t.Fatalf("%d addresses reported, over the %d bound", len(addrs), maxReportedAddresses)
	}
	seenV6 := false
	for _, s := range addrs {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("%q is not an address", s)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
			t.Fatalf("%q should not be reported", s)
		}
		if ip.To4() != nil && seenV6 {
			t.Fatalf("IPv4 %q after an IPv6 address; the family order is what the plane prefers by", s)
		}
		if ip.To4() == nil {
			seenV6 = true
		}
	}
}

// Docker's bridges are never stated: nothing outside the machine routes to
// them, and a container's request to this host arrives from one.
func TestContainerBridgesAreLeftOut(t *testing.T) {
	for _, name := range []string{"docker0", "br-3f2a9c1d0e4b", "docker_gwbridge", "veth1a2b3c4"} {
		if !containerBridge(name) {
			t.Errorf("%s should be left out", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0", "wg0", "bridge0", "lo"} {
		if containerBridge(name) {
			t.Errorf("%s is not Docker's and should be stated", name)
		}
	}
}

// A bridge named by whoever made it is judged by its ports: a shared host's
// site networks (jsnet1, ports only containers' veth ends, or none yet) are
// left out; a bridge that carries the machine's uplink is not (B47).
func TestBridgesWithOnlyContainerPortsAreLeftOut(t *testing.T) {
	root := t.TempDir()
	bridge := func(name string, ports ...string) {
		if err := os.MkdirAll(filepath.Join(root, name, "bridge"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, name, "brif"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, p := range ports {
			if err := os.WriteFile(filepath.Join(root, name, "brif", p), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	bridge("jsnet1", "veth9a8b7c6", "veth1d2e3f4")
	bridge("jsnet2")
	bridge("br0", "eth0")
	bridge("lan0", "enp1s0", "veth5a6b7c8")
	if err := os.MkdirAll(filepath.Join(root, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := sysClassNet
	sysClassNet = root
	defer func() { sysClassNet = old }()
	for _, name := range []string{"jsnet1", "jsnet2"} {
		if !containerBridge(name) {
			t.Errorf("%s holds only containers and should be left out", name)
		}
	}
	for _, name := range []string{"br0", "lan0", "eth0"} {
		if containerBridge(name) {
			t.Errorf("%s carries the machine's own network and should be stated", name)
		}
	}
}
