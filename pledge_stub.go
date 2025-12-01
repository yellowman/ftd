//go:build !openbsd
// +build !openbsd

package main

func applyPledgeInitial(useTCP bool) error { return nil }
func applyPledgePostDB(useTCP bool) error  { return nil }
func applyPledgeRuntime(useTCP bool) error { return nil }
