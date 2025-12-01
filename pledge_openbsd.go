//go:build openbsd
// +build openbsd

package main

import "syscall"

// applyPledgeInitial sets a permissive pledge needed during startup to open sockets
// and perform user lookups before dropping privileges. Includes unix promises only
// when a Unix FastCGI socket (or other Unix connections like Postgres sockets) is used.
func applyPledgeInitial(allowUnix bool) error {
	// stdio: basic I/O
	// rpath/wpath/cpath: read/write/create paths for socket setup and config reads
	// inet/unix: PostgreSQL connections and admin listener
	// dns: resolve PostgreSQL hostnames
	// getpw/id: user lookups and privilege drops
	promises := "stdio rpath wpath cpath inet dns getpw id"
	if allowUnix {
		promises += " unix"
	}
	return syscall.Pledge(promises, nil)
}

// applyPledgePostDB tightens after the PostgreSQL connection has been established
// and we no longer need DNS or account lookups.
func applyPledgePostDB(allowUnix bool) error {
	promises := "stdio rpath wpath cpath inet"
	if allowUnix {
		promises += " unix"
	}
	return syscall.Pledge(promises, nil)
}

// applyPledgeRuntime further narrows capabilities once sockets are created.
func applyPledgeRuntime(allowUnix bool) error {
	promises := "stdio inet"
	if allowUnix {
		promises += " unix"
	}
	return syscall.Pledge(promises, nil)
}
