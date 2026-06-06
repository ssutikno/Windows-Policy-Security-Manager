//go:build !windows
// +build !windows

package main

import (
	"os"
)

func checkAdminPrivileges() bool {
	return os.Geteuid() == 0
}
