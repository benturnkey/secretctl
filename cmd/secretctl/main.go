package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkhq/secretctl/internal/command"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	os.Exit(command.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.LookupEnv))
}
