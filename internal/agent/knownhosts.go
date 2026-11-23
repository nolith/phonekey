package agent

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// hostNames looks up a host key in known_hosts files and returns the names
// it's recorded under. Hashed entries can only be matched against candidate
// names (taken from the ssh command line). known reports whether the key
// appears at all, even under names that couldn't be recovered.
func hostNames(files []string, key ssh.PublicKey, candidates []string) (names []string, known bool) {
	want := key.Marshal()
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' || line[0] == '@' {
				// @cert-authority and @revoked lines don't name a host key.
				continue
			}
			hosts, rest, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(rest)))
			if err != nil || !bytes.Equal(k.Marshal(), want) {
				continue
			}
			known = true
			for _, h := range strings.Split(hosts, ",") {
				switch {
				case strings.HasPrefix(h, "|1|"):
					for _, c := range candidates {
						if hashedHostMatches(h, c) {
							add(c)
						}
					}
				case strings.ContainsAny(h, "*?!"):
				default:
					add(h)
				}
			}
		}
		f.Close()
	}
	return names, known
}

func hashedHostMatches(entry, host string) bool {
	parts := strings.Split(entry, "|")
	if len(parts) != 4 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	sum, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	m := hmac.New(sha1.New, salt)
	m.Write([]byte(host))
	return hmac.Equal(m.Sum(nil), sum)
}

// hostCandidates turns an ssh destination into the names known_hosts would
// record it under.
func hostCandidates(dest, port string) []string {
	if dest == "" {
		return nil
	}
	if strings.HasPrefix(dest, "ssh://") {
		dest = strings.TrimPrefix(dest, "ssh://")
		if h, p, ok := strings.Cut(dest, ":"); ok {
			dest, port = h, strings.TrimSuffix(p, "/")
		}
	}
	if i := strings.LastIndexByte(dest, '@'); i >= 0 {
		dest = dest[i+1:]
	}
	if port != "" && port != "22" {
		return []string{"[" + dest + "]:" + port}
	}
	return []string{dest}
}
