package main

import "os/exec"

func runFixedCmd() {
	exec.Command("ls", "-la")
}
