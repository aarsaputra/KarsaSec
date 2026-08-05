package main

import (
    "context"
    "os"
    "os/exec"
)

func runContextRegression(ctx context.Context) {
    inputTarget := os.Args[1]
    exec.CommandContext(ctx, "ping", inputTarget)
}
