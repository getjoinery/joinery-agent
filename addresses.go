package main

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxReportedAddresses bounds what a join carries; a machine with more has
// something unusual going on and the first sixteen are enough to match a
// placement record by.
const maxReportedAddresses = 16

// containerBridge reports an interface made for containers: docker0, a user
// network's br-<id>, the swarm gateway, a container's veth end, and any
// bridge whose only ports are containers' (a Docker network given a name of
// its own, as a shared host's site networks are: jsnet1, jsnet2). Their
// addresses are this machine's side of a private network nothing outside it
// routes to, and through Docker's port forwarding a container's request to a
// service on this host arrives FROM the bridge's address: stated, it would
// let a co-tenant container ask as this machine.
func containerBridge(name string) bool {
	return name == "docker0" || name == "docker_gwbridge" ||
		strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") ||
		containerOnlyBridge(sysClassNet, name)
}

// sysClassNet is where the kernel lists this machine's interfaces.
var sysClassNet = "/sys/class/net"

// containerOnlyBridge reports a Linux bridge with no port but containers'
// veth ends, or none at all yet. A machine whose uplink is a bridge (br0 over
// eth0) has a port that is not a container's, and keeps its address.
func containerOnlyBridge(root, name string) bool {
	if _, err := os.Stat(filepath.Join(root, name, "bridge")); err != nil {
		return false
	}
	ports, err := os.ReadDir(filepath.Join(root, name, "brif"))
	if err != nil {
		return false
	}
	for _, p := range ports {
		if !strings.HasPrefix(p.Name(), "veth") {
			return false
		}
	}
	return true
}

// machineAddresses is every global unicast address on this machine's
// interfaces, IPv4 first, each family sorted, loopback, link-local and
// Docker's bridges left out. It is what a join sends so the plane can match this machine to the
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
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || containerBridge(iface.Name) {
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
