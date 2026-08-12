package main

import "syscall"

// Not exported by the syscall package; see CreateProcess dwCreationFlags.
const detachedProcess = 0x00000008

// daemonSysProcAttr detaches the daemon child from the parent console so it
// survives the terminal closing and receives no Ctrl+C events (shutdown is
// via POST /logout, matching the Unix logout path).
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}
