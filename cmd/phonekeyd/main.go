// Command phonekeyd queues signature requests from dev boxes, notifies the
// phone and serves the approval web app.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"tailscale.com/tsnet"

	"phonekey/internal/protocol"
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
  keys rm FINGERPRINT|ID
                      remove a key: its logins end and its pending requests are denied
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
		err = serve(ctx, st, *dbPath, args[1:])
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

func serve(ctx context.Context, st *store.Store, dbPath string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", os.Getenv("PHONEKEY_ADDR"),
		"plain HTTP listen address, host:port or unix:/path (default 127.0.0.1:8080, or none with --tailscale-hostname) ($PHONEKEY_ADDR)")
	tsHostname := fs.String("tailscale-hostname", os.Getenv("PHONEKEY_TS_HOSTNAME"),
		"also join the tailnet as this machine name and serve HTTPS at https://NAME.<tailnet>.ts.net ($PHONEKEY_TS_HOSTNAME)")
	tsDir := fs.String("tailscale-dir", "", "tailnet node state (default: tailscale/ next to the database)")
	tsKeyFile := fs.String("tailscale-authkey-file", os.Getenv("PHONEKEY_TS_AUTHKEY_FILE"),
		"Tailscale auth key for the first login; without one (or $TS_AUTHKEY) a login URL is logged ($PHONEKEY_TS_AUTHKEY_FILE)")
	var cfg server.Config
	fs.StringVar(&cfg.RPName, "rp-name", "phonekey", "WebAuthn RP display name")
	fs.StringVar(&cfg.Salt, "salt", "", "PRF salt (default phonekey/ssh-ed25519/v1)")
	fs.StringVar(&cfg.VAPIDSubject, "vapid-subject", os.Getenv("PHONEKEY_VAPID_SUBJECT"),
		"VAPID subject, an email address or https: URL; Apple rejects placeholders ($PHONEKEY_VAPID_SUBJECT)")
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

	// On its own tailnet machine phonekeyd is reachable only through the
	// tailnet unless a plain listener is asked for explicitly.
	if *addr == "" && *tsHostname == "" {
		*addr = "127.0.0.1:8080"
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	errc := make(chan error, 2)
	if *addr != "" {
		ln, err := listenPlain(*addr)
		if err != nil {
			return err
		}
		cfg.Logger.Info("listening", "addr", *addr)
		go func() { errc <- hs.Serve(ln) }()
	}
	if *tsHostname != "" {
		dir := *tsDir
		if dir == "" {
			dir = filepath.Join(filepath.Dir(dbPath), "tailscale")
		}
		ln, err := listenTailnet(ctx, cfg.Logger, *tsHostname, dir, *tsKeyFile, *verbose)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tailnet: %w", err)
		}
		go func() { errc <- hs.Serve(ln) }()
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listenPlain listens on host:port, or on unix:/path. A Unix socket is
// created for phonekeyd's own account and group only (and root, e.g. a
// tailscaled proxying to it); a reverse proxy gets access by joining the
// group.
func listenPlain(addr string) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return net.Listen("tcp", addr)
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s is in use", path)
	}
	os.Remove(path)
	old := syscall.Umask(0o117)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

// listenTailnet joins the tailnet as its own machine (no root or tailscaled
// configuration needed) and listens for HTTPS on port 443 with the
// machine's *.ts.net certificate. The tailnet needs MagicDNS and HTTPS
// certificates enabled. On first start it logs in with the auth key, or logs
// a URL to approve the machine and waits.
func listenTailnet(ctx context.Context, log *slog.Logger, hostname, dir, keyFile string, verbose bool) (net.Listener, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ts := &tsnet.Server{
		Hostname: hostname,
		Dir:      dir,
		UserLogf: func(format string, args ...any) { log.Info("tailscale: " + fmt.Sprintf(format, args...)) },
		Logf:     func(string, ...any) {},
	}
	if verbose {
		ts.Logf = func(format string, args ...any) { log.Debug("tailscale: " + fmt.Sprintf(format, args...)) }
	}
	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		ts.AuthKey = strings.TrimSpace(string(key))
	}
	log.Info("joining the tailnet", "hostname", hostname, "state", dir)
	// ListenTLS waits until the machine is logged in, which may take a
	// person approving it, so don't let it hold up shutdown.
	type result struct {
		ln  net.Listener
		err error
	}
	done := make(chan result, 1)
	go func() {
		ln, err := ts.ListenTLS("tcp", ":443")
		done <- result{ln, err}
	}()
	var ln net.Listener
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		ln = r.ln
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	context.AfterFunc(ctx, func() { ts.Close() })
	for _, d := range ts.CertDomains() {
		log.Info("listening", "url", "https://"+d)
	}
	return ln, nil
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
		k, err := st.RemoveKey(ctx, args[1])
		if err == nil {
			fmt.Printf("removed %s (%s)\n", protocol.CleanLabel(k.Label), k.Fingerprint)
		}
		return err
	}
	ks, err := st.Keys(ctx)
	if err != nil {
		return err
	}
	for _, k := range ks {
		fmt.Printf("%s %s  # %s, %s, %d logins, %d with notifications\n", k.PublicKey, protocol.CleanLabel(k.Label), k.Fingerprint,
			time.Unix(k.CreatedAt, 0).Format(time.DateOnly), k.Logins, k.Notified)
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
