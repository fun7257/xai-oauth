//go:build unix

package main

import "syscall"

// daemonSysProcAttr detaches the daemon child into its own session so it
// survives the parent terminal closing.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
