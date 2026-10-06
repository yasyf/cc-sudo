// Command synckit-fixture serves synckitd's business lane on a real daemonkit
// protocol-2 socket under -home, answering every synckit.rpc.call with the
// -reply body. It prints READY <socket> once a call round-trips, then one
// REQUEST <op> <base64 body> line per call, and exits on stdin EOF.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/daemonkit/paths"
	"github.com/yasyf/synckit/rpc"
)

const (
	label       = "com.github.yasyf.synckit.serve"
	probeMethod = "synckit-fixture.ready"
	readyBudget = 20 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "synckit-fixture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	home := flag.String("home", "", "the home the daemon's layout is rooted at (required)")
	reply := flag.String("reply", "", "the raw synckit.rpc.call response body (required)")
	flag.Parse()
	if *home == "" || *reply == "" {
		return errors.New("-home and -reply are required")
	}
	if err := os.Setenv("DAEMONKIT_HOME", *home); err != nil {
		return err
	}

	spec := daemonkit.Daemon{
		Label:    daemonkit.Label(label),
		Schemas:  []daemonkit.Schema{rpc.WireBuild},
		Trust:    daemonkit.Trust{Serving: daemonkit.ServingSameUser()},
		Shutdown: daemonkit.Grace(5 * time.Second),
		MaxFrame: rpc.MaxFrame,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		stop()
	}()

	out := &output{}
	served := make(chan error, 1)
	go func() {
		_, err := daemonkit.Serve(ctx, spec, func(daemonkit.Ctx) (daemonkit.Product, error) {
			return product{reply: []byte(*reply), out: out}, nil
		})
		served <- err
	}()

	if err := waitReady(ctx, spec); err != nil {
		stop()
		return errors.Join(err, <-served)
	}
	out.printf("READY %s\n", paths.Agent(label).SocketPath())
	return <-served
}

func waitReady(ctx context.Context, spec daemonkit.Daemon) error {
	client, err := daemonkit.Open(spec)
	if err != nil {
		return err
	}
	business := client.Business()
	defer func() { _ = business.Close(context.WithoutCancel(ctx)) }()
	probe, err := json.Marshal(rpc.Request{Method: probeMethod})
	if err != nil {
		return err
	}
	deadline := time.Now().Add(readyBudget)
	for {
		callCtx, cancel := context.WithTimeout(ctx, time.Second)
		_, err := business.Call(callCtx, "synckit.rpc.call", probe)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon never answered: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type output struct{ mu sync.Mutex }

func (o *output) printf(format string, args ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Printf(format, args...)
}

type product struct {
	reply []byte
	out   *output
}

func (p product) Handle(_ context.Context, req daemonkit.Request) (daemonkit.Reply, error) {
	var call rpc.Request
	if err := json.Unmarshal(req.Body, &call); err == nil && call.Method == probeMethod {
		return daemonkit.Reply{Body: []byte(`{"ok":true,"result":null}`)}, nil
	}
	p.out.printf("REQUEST %s %s\n", req.Op, base64.StdEncoding.EncodeToString(req.Body))
	return daemonkit.Reply{Body: p.reply}, nil
}

func (product) Drain(daemonkit.Budget) error { return nil }

func (product) Close(daemonkit.Budget) error { return nil }
