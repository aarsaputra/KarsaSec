package main

import "os/exec"

func runCmd(inputStr string) {
	exec.Command("sh", "-c", inputStr)
}
