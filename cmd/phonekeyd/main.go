// Command phonekeyd queues signature requests from dev boxes, notifies the
// phone and serves the approval web app.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"phonekey/internal/server"
	"phonekey/internal/store"
)

const usage = `usage: phonekeyd [--db PATH] <command> [flags]

commands:
  serve               run the server
  pair-code           print a one-time code for pairing a passkey (valid 10 minutes)
  devbox add NAME     register a dev box and print its token
  devbox list
  devbox rm NAME
  keys                list registered public keys
  keys rm FINGERPRINT
`

func main() {
	global := flag.NewFlagSet("phonekeyd", flag.ExitOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage); global.PrintDefaults() }
	dbPath := global.String("db", envOr("PHONEKEY_DB", "phonekey.db"), "SQLite database path ($PHONEKEY_DB)")
	global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		global.Usage()
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	switch args[0] {
	case "serve":
		err = serve(ctx, st, args[1:])
	case "pair-code":
		var code string
		if code, err = st.NewPairCode(ctx, 10*time.Minute); err == nil {
			fmt.Println(code)
		}
	case "devbox":
		err = devbox(ctx, st, args[1:])
	case "keys":
		err = keys(ctx, st, args[1:])
	default:
		global.Usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func serve(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", envOr("PHONEKEY_ADDR", "127.0.0.1:8080"), "listen address ($PHONEKEY_ADDR)")
	var cfg server.Config
	fs.StringVar(&cfg.RPID, "rp-id", os.Getenv("PHONEKEY_RP_ID"), "WebAuthn RP ID (default: the page's hostname) ($PHONEKEY_RP_ID)")
	fs.StringVar(&cfg.RPName, "rp-name", "phonekey", "WebAuthn RP display name")
	fs.StringVar(&cfg.Salt, "salt", "", "PRF salt (default phonekey/ssh-ed25519/v1)")
	fs.StringVar(&cfg.VAPIDSubject, "vapid-subject", os.Getenv("PHONEKEY_VAPID_SUBJECT"),
		"VAPID subject, a mailto: or https: URL; Apple rejects placeholders ($PHONEKEY_VAPID_SUBJECT)")
	fs.DurationVar(&cfg.DefaultTTL, "default-ttl", 90*time.Second, "request lifetime when the agent doesn't ask for one")
	fs.DurationVar(&cfg.MaxTTL, "max-ttl", 5*time.Minute, "longest request lifetime an agent may ask for")
	fs.DurationVar(&cfg.SessionTTL, "session-ttl", 30*24*time.Hour, "web session lifetime")
	fs.DurationVar(&cfg.Retention, "retention", 7*24*time.Hour, "how long resolved requests are kept as history")
	fs.DurationVar(&cfg.MaxGrant, "max-grant", 60*time.Second, "longest grant the page may offer (0 disables grants)")
	fs.BoolVar(&cfg.AllowUnknownKinds, "allow-unknown-kinds", false, "accept data that's neither SSH userauth nor SSHSIG")
	origins := fs.String("origins", "", "comma-separated extra origins allowed for web API writes")
	verbose := fs.Bool("v", false, "debug logging")
	fs.Parse(args)
	if *origins != "" {
		cfg.Origins = strings.Split(*origins, ",")
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if cfg.VAPIDSubject == "" {
		cfg.Logger.Warn("no --vapid-subject set; Apple's push service may reject the placeholder")
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, st, cfg)
	if err != nil {
		return err
	}
	go srv.Sweep(ctx, 5*time.Second)
	hs := &http.Server{Addr: *addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	cfg.Logger.Info("listening", "addr", *addr)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func devbox(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("devbox: missing subcommand (add, list, rm)")
	}
	switch {
	case args[0] == "add" && len(args) == 2:
		token, err := st.AddDevbox(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Println(token)
	case args[0] == "list":
		ds, err := st.Devboxes(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tCREATED\tLAST SEEN")
		for _, d := range ds {
			seen := "never"
			if d.LastSeenAt.Valid {
				seen = time.Unix(d.LastSeenAt.Int64, 0).Format(time.DateTime)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", d.Name, time.Unix(d.CreatedAt, 0).Format(time.DateTime), seen)
		}
		w.Flush()
	case args[0] == "rm" && len(args) == 2:
		return st.RemoveDevbox(ctx, args[1])
	default:
		return errors.New("devbox: usage: devbox add NAME | list | rm NAME")
	}
	return nil
}

func keys(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 2 && args[0] == "rm" {
		return st.RemoveKey(ctx, args[1])
	}
	ks, err := st.Keys(ctx)
	if err != nil {
		return err
	}
	for _, k := range ks {
		fmt.Printf("%s %s  # %s, %s\n", k.PublicKey, k.Label, k.Fingerprint, time.Unix(k.CreatedAt, 0).Format(time.DateOnly))
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "phonekeyd:", err)
	os.Exit(1)
}
