// Command phonekey-sim stands in for the phone: it derives a key from a fixed
// "PRF output" and pairs, approves or denies through phonekeyd's web API.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"phonekey/internal/protocol"
	"phonekey/internal/sim"
)

const usage = `usage: phonekey-sim [flags] <command>

commands:
  pubkey              print the derived public key
  pair CODE [LABEL]   register the key with a pairing code
  list                print pending requests
  watch               approve (or with --ask, prompt for) each request as it arrives
  deny ID
`

func main() {
	url := flag.String("url", envOr("PHONEKEY_URL", "http://localhost:8080"), "phonekeyd URL ($PHONEKEY_URL)")
	secret := flag.String("secret", envOr("PHONEKEY_SIM_SECRET", "phonekey-sim"),
		"stands in for the passkey: PRF output = SHA-256(secret) ($PHONEKEY_SIM_SECRET)")
	ask := flag.Bool("ask", false, "watch: prompt before approving each request")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage); flag.PrintDefaults() }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	prf := sha256.Sum256([]byte(*secret))
	p := sim.New(*url, prf[:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args := flag.Args(); args[0] {
	case "pubkey":
		fmt.Println(p.PublicKey())
	case "pair":
		if len(args) < 2 {
			flag.Usage()
			os.Exit(2)
		}
		label := "phonekey-sim"
		if len(args) > 2 {
			label = args[2]
		}
		if err = p.Pair(ctx, args[1], label); err == nil {
			fmt.Println("paired", p.PublicKey())
		}
	case "list":
		var reqs []protocol.WebRequest
		if err = p.Login(ctx); err == nil {
			if reqs, err = p.Pending(ctx); err == nil {
				for _, r := range reqs {
					fmt.Printf("%s  %s  [%s]\n", r.ID, r.Summary, r.Details.Kind)
				}
			}
		}
	case "deny":
		if err = p.Login(ctx); err == nil && len(args) > 1 {
			err = p.Deny(ctx, args[1])
		}
	case "watch":
		err = watch(ctx, p, *ask)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "phonekey-sim:", err)
		os.Exit(1)
	}
}

func watch(ctx context.Context, p *sim.Phone, ask bool) error {
	if err := p.Login(ctx); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "watching for requests as", p.PublicKey())
	in := bufio.NewReader(os.Stdin)
	handled := map[string]bool{}
	return p.Watch(ctx, func(reqs []protocol.WebRequest) error {
		for _, r := range reqs {
			if handled[r.ID] {
				continue
			}
			handled[r.ID] = true
			fmt.Fprintf(os.Stderr, "%s  %s\n", r.ID, r.Summary)
			if b, err := jsonIndent(r); err == nil {
				fmt.Fprintln(os.Stderr, b)
			}
			if ask {
				fmt.Fprint(os.Stderr, "approve? [y/N] ")
				line, _ := in.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(line), "y") {
					if err := p.Deny(ctx, r.ID); err != nil {
						fmt.Fprintln(os.Stderr, "  deny failed:", err)
					}
					continue
				}
			}
			if err := p.Approve(ctx, r); err != nil {
				fmt.Fprintln(os.Stderr, "  approve failed:", err)
			} else {
				fmt.Fprintln(os.Stderr, "  approved")
			}
		}
		return nil
	})
}

func jsonIndent(r protocol.WebRequest) (string, error) {
	b, err := json.MarshalIndent(struct {
		Details any `json:"details"`
		Context any `json:"context"`
	}{r.Details, r.Context}, "  ", "  ")
	return "  " + string(b), err
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
