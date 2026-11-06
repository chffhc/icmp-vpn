package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"icmpvpn/server/vpn"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: icmpvpn keygen|serve|tcpaccel [flags]")
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
		path := fs.String("key-file", "", "new raw PSK file (0600, exclusive creation)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" || fs.NArg() != 0 {
			return errors.New("keygen requires --key-file path")
		}
		if err := vpn.GenerateKey(*path); err != nil {
			return err
		}
		log.Printf("created key file %s (key not printed)", *path)
		return nil
	case "tcpaccel":
		return runTCPAccel(args[1:])
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		keyPath := fs.String("key-file", "", "raw 32-byte PSK file (0600)")
		tun := fs.String("tun", "icmpvpn0", "preconfigured persistent TUN interface")
		listen := fs.String("listen", "0.0.0.0", "literal local IPv4 to bind raw ICMP")
		state := fs.String("state-file", "", "durable used-session ledger (default KEY.sessions)")
		capacity := fs.Int("max-sessions", 4096, "bounded lifetime session reservations, 1..65536")
		discipline := fs.String("queue-discipline", string(vpn.QueueFIFO), "downstream queue: fifo or fq-codel (experimental opt-in)")
		queueLimit := fs.Int("queue-limit", vpn.DefaultQueueLimit, "bounded downstream packets, 1..4096 (default 256)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *keyPath == "" || fs.NArg() != 0 {
			return errors.New("serve requires --key-file path")
		}
		if *discipline == "" {
			return errors.New("unknown queue discipline: empty (want fifo or fq-codel)")
		}
		if err := vpn.ValidateQueueOptions(vpn.QueueDiscipline(*discipline), *queueLimit); err != nil {
			return err
		}
		if *queueLimit == 0 {
			return errors.New("invalid queue limit 0 (want 1..4096)")
		}
		addr, err := netip.ParseAddr(*listen)
		if err != nil || !addr.Is4() {
			return errors.New("--listen must be literal IPv4")
		}
		key, err := vpn.ReadKey(*keyPath)
		if err != nil {
			return fmt.Errorf("key: %w", err)
		}
		if *state == "" {
			*state = *keyPath + ".sessions"
		}
		store, err := vpn.OpenFileStore(*state, key, *capacity)
		if err != nil {
			return fmt.Errorf("session ledger: %w", err)
		}
		defer store.Close()
		engine, err := vpn.NewEngine(key, vpn.Options{Store: store, MaxSessions: *capacity, QueueDiscipline: vpn.QueueDiscipline(*discipline), QueueLimit: *queueLimit})
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return serve(ctx, engine, *tun, addr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
