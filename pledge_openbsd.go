//go:build openbsd
// +build openbsd

package main

import "golang.org/x/sys/unix"

// applyPledgeRuntime is the single, final sandbox applied once all privileged
// setup is complete: sockets are open, the PostgreSQL connection is
// established, and (when started as root) the process has already chrooted and
// dropped privileges.
//
// pledge(2) must be the last step because it is a one-way ratchet and neither
// chroot(2) nor the setuid family is permitted by any promise — so those must
// run while the process is still unpledged.
//
//   - stdio: basic I/O, getentropy, and the like
//   - rpath: the Go runtime and the pq driver read files during normal
//     operation and on reconnect (e.g. /etc/resolv.conf, /etc/hosts, timezone
//     data); without this the first such open(2) aborts the process
//   - inet:  TCP admin listener and/or PostgreSQL over TCP
//   - dns:   re-resolve the PostgreSQL host if the connection is re-established
//   - unix:  Unix FastCGI socket and/or PostgreSQL over a Unix socket
//   - wpath/cpath: only when uploads are enabled, to create and write files
//     under the uploads directory inside the chroot
func applyPledgeRuntime(allowUnix, allowUploads bool) error {
	promises := "stdio rpath inet dns"
	if allowUnix {
		promises += " unix"
	}
	if allowUploads {
		promises += " wpath cpath"
	}
	return unix.PledgePromises(promises)
}
