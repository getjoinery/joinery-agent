package main

import (
	"net"
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
