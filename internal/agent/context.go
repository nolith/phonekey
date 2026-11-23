package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
)

type proc struct {
	pid, ppid int
	comm      string
	args      []string
	start     string
	cwd       string
}

const maxChain = 10

// processChain returns pid and its ancestors, nearest first.
func processChain(pid int) []proc {
	var chain []proc
	for pid > 1 && len(chain) < maxChain {
		p, err := readProc(pid)
		if err != nil {
			break
		}
		chain = append(chain, p)
		pid = p.ppid
	}
	return chain
}

func isTool(comm string) bool {
	switch comm {
	case "ssh", "ssh-keygen", "jj", "git", "phonekey-keygen":
		return true
	}
	return strings.HasPrefix(comm, "git-")
}

// toolRun returns how many processes, starting at the peer, form an unbroken
// run of git/jj/ssh processes: one `jj git push` or one `git rebase -S`.
func toolRun(chain []proc) int {
	n := min(1, len(chain))
	for n < len(chain) && isTool(chain[n].comm) {
		n++
	}
	return n
}

// scope identifies the outermost process of the tool run, so every signature
// one jj or git invocation asks for gets the same scope.
func scope(chain []proc) string {
	if len(chain) == 0 {
		return ""
	}
	top := chain[toolRun(chain)-1]
	return fmt.Sprintf("%d:%s", top.pid, top.start)
}

// sshOptsWithArg are ssh(1) flags that consume the next argument.
const sshOptsWithArg = "BbcDEeFIiJLlmOoPpQRSWw"

// parseSSHArgs extracts the destination, port and remote command from an
// ssh command line.
func parseSSHArgs(args []string) (dest, port string, command []string) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			if i < len(args) {
				return args[i], port, args[i+1:]
			}
			return "", port, nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return a, port, args[i+1:]
		}
		// Flags may be bundled (-4vp 22) or joined to their value (-p22).
		for j := 1; j < len(a); j++ {
			if strings.IndexByte(sshOptsWithArg, a[j]) < 0 {
				continue
			}
			val := a[j+1:]
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
			if a[j] == 'p' {
				port = val
			}
			break
		}
	}
	return "", port, nil
}

// gitAction turns a remote git command into "push to repo" and the like.
func gitAction(command []string) string {
	cmd := strings.Join(command, " ")
	for verb, service := range map[string]string{
		"push to":         "git-receive-pack",
		"fetch from":      "git-upload-pack",
		"archive from":    "git-upload-archive",
		"LFS access to":   "git-lfs-authenticate",
		"transfer within": "git-lfs-transfer",
	} {
		if rest, ok := strings.CutPrefix(cmd, service); ok {
			repo := strings.Trim(strings.TrimSpace(rest), "'\"")
			if f := strings.Fields(repo); len(f) > 0 {
				repo = strings.Trim(f[0], "'\"")
			}
			return verb + " " + strings.TrimSuffix(strings.TrimPrefix(repo, "/"), ".git")
		}
	}
	if cmd != "" {
		return "run " + truncate(cmd, 80)
	}
	return ""
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// commandLine is the nearest git or jj ancestor's command line, which is the
// best description of why ssh-keygen or ssh is running.
func commandLine(chain []proc) string {
	var best []string
	for _, p := range chain {
		if p.comm == "git" || p.comm == "jj" {
			best = p.args
		}
	}
	if best == nil {
		return ""
	}
	parts := make([]string, len(best))
	for i, a := range best {
		if i == 0 {
			a = filepath.Base(a)
		}
		parts[i] = a
	}
	return truncate(strings.Join(parts, " "), 120)
}

// buildContext describes the peer process for the approver.
func buildContext(hostname string, chain []proc, data []byte) protocol.Context {
	c := protocol.Context{Host: hostname, Scope: scope(chain)}
	// The tool run and whatever started it (usually a shell), but nothing
	// further up: unrelated command lines don't belong on the backend.
	for _, p := range chain[:min(toolRun(chain)+1, len(chain))] {
		c.Processes = append(c.Processes, protocol.Process{PID: p.pid, Command: p.comm, Args: p.args})
	}
	if len(chain) == 0 {
		return c
	}
	peer := chain[0]
	switch peer.comm {
	case "ssh":
		dest, port, command := parseSSHArgs(peer.args)
		c.Remote = dest
		if port != "" && port != "22" {
			c.Remote += ":" + port
		}
		c.Action = gitAction(command)
	case "ssh-keygen":
		c.Action = commandLine(chain)
		if obj := signedGitObject(peer, data); obj != nil {
			c.GitObject = obj
		}
	default:
		c.Action = commandLine(chain)
	}
	return c
}

// signedGitObject reads the file ssh-keygen -Y sign was given (git passes the
// object in a temporary file; jj pipes it through stdin, so there's nothing
// to read) and parses it if its hash matches the SSHSIG blob.
func signedGitObject(p proc, data []byte) *protocol.GitObject {
	sig, err := sshwire.ParseSSHSig(data)
	if err != nil || sig.Namespace != "git" || len(p.args) < 2 {
		return nil
	}
	path := p.args[len(p.args)-1]
	if strings.HasPrefix(path, "-") {
		return nil
	}
	if !filepath.IsAbs(path) && p.cwd != "" {
		path = filepath.Join(p.cwd, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil
	}
	var h hash.Hash
	switch sig.HashAlgorithm {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return nil
	}
	h.Write(content)
	if !bytes.Equal(h.Sum(nil), sig.Hash) {
		return nil
	}
	return parseGitObject(content)
}

func parseGitObject(content []byte) *protocol.GitObject {
	header, message, _ := bytes.Cut(content, []byte("\n\n"))
	obj := &protocol.GitObject{Type: "commit"}
	for _, line := range strings.Split(string(header), "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "author":
			obj.Author = stripTimestamp(v)
		case "committer":
			obj.Committer = stripTimestamp(v)
		case "tagger":
			obj.Tagger = stripTimestamp(v)
		case "parent":
			obj.Parents++
		case "tag":
			obj.Tag = v
			obj.Type = "tag"
		}
	}
	subject, body, _ := strings.Cut(strings.TrimSpace(string(message)), "\n")
	obj.Subject = subject
	obj.Body = truncate(strings.TrimSpace(body), 1000)
	return obj
}

// stripTimestamp turns "Name <email> 1700000000 +0100" into "Name <email>".
func stripTimestamp(s string) string {
	if i := strings.LastIndexByte(s, '>'); i >= 0 {
		return s[:i+1]
	}
	return s
}
