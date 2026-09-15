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
