package main

import (
	"context"
	"os/exec"
)

func runContextRegression(ctx context.Context, inputTarget string) {
	exec.CommandContext(ctx, "ping", inputTarget)
}
