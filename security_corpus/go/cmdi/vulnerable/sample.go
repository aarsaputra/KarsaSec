package main

import (
    "os"
    "os/exec"
)

func runCmd() {
    inputStr := os.Args[1]
    exec.Command("sh", "-c", inputStr)
}
