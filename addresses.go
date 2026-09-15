package main

import (
	"net"
	"sort"
)

// maxReportedAddresses bounds what a join carries; a machine with more has
// something unusual going on and the first sixteen are enough to match a
// placement record by.
const maxReportedAddresses = 16

// machineAddresses is every global unicast address on this machine's
// interfaces, IPv4 first, each family sorted, loopback and link-local left
// out. It is what a join sends so the plane can match this machine to the
// placement record it already holds, whichever family the request travelled
// over. Nothing here is trusted by the plane beyond "an address this machine
// claims"; the plane validates each as an address and matches only against
// records it already has.
func machineAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var v4, v6 []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP == nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				v4 = append(v4, ip4.String())
			} else {
				v6 = append(v6, ipn.IP.String())
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	out := append(v4, v6...)
	if len(out) > maxReportedAddresses {
		out = out[:maxReportedAddresses]
	}
	return out
}
