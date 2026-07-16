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
//   - inet:  TCP admin listener and/or PostgreSQL over TCP
//   - unix:  Unix FastCGI socket and/or PostgreSQL over a Unix socket
//   - rpath/wpath/cpath: only when uploads are enabled, to create and write
//     files under the uploads directory inside the chroot
func applyPledgeRuntime(allowUnix, allowUploads bool) error {
	promises := "stdio inet"
	if allowUnix {
		promises += " unix"
	}
	if allowUploads {
		promises += " rpath wpath cpath"
	}
	return unix.PledgePromises(promises)
}
