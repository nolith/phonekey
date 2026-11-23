// Command phonekey-keygen wraps ssh-keygen for jj's ssh signing backend.
//
// jj pipes the object to sign through ssh-keygen's stdin, which leaves
// phonekey-agent nothing to show on the phone but the jj command line. git
// instead passes a file, which the agent reads and checks against the hash
// it's asked to sign. This shim makes jj's signing look like git's: it spools
// stdin to a temporary file, runs `ssh-keygen ... FILE`, and prints FILE.sig
// on stdout where jj expects the signature. Everything other than
// `-Y sign` without a file argument is passed through unchanged.
//
// jj config:
//
//	[signing.backends.ssh]
//	program = "phonekey-keygen"
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

func main() {
	keygen := os.Getenv("PHONEKEY_SSH_KEYGEN")
	if keygen == "" {
		keygen = "ssh-keygen"
	}
	args := os.Args[1:]
	if !signsStdin(args) {
		os.Exit(run(keygen, args, os.Stdin, os.Stdout))
	}
	dir, err := os.MkdirTemp("", "phonekey-keygen-")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "object")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fail(err)
	}
	if _, err := io.Copy(f, os.Stdin); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	if code := run(keygen, append(slices.Clone(args), file), nil, os.Stderr); code != 0 {
		os.Exit(code)
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		fail(err)
	}
	os.Stdout.Write(sig)
}

// signsStdin reports whether args ask ssh-keygen to sign stdin: "-Y sign"
// with only flags (and their values) after it.
func signsStdin(args []string) bool {
	i := slices.Index(args, "-Y")
	if i < 0 || i+1 >= len(args) || args[i+1] != "sign" {
		return false
	}
	for j := 0; j < len(args); j++ {
		switch a := args[j]; {
		case a == "-Y" || a == "-f" || a == "-n" || a == "-O" || a == "-I" || a == "-s":
			j++
		case a == "-U" || a == "-q" || a == "-v":
		default:
			return false // a file argument, or a flag we don't know
		}
	}
	return true
}

func run(name string, args []string, stdin io.Reader, stdout io.Writer) int {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fail(err)
	}
	return 0
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "phonekey-keygen:", err)
	os.Exit(1)
}
