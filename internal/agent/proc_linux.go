package agent

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func peerPID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	var cred *unix.Ucred
	raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return 0
	}
	return int(cred.Pid)
}

// readProc returns a process's command name, arguments, parent pid and start
// time (in clock ticks since boot, which disambiguates reused pids).
func readProc(pid int) (proc, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return proc{}, err
	}
	// comm is parenthesized and may contain spaces or parens itself.
	open, close := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || close < open {
		return proc{}, fmt.Errorf("malformed stat for %d", pid)
	}
	fields := strings.Fields(string(stat[close+1:]))
	if len(fields) < 20 {
		return proc{}, fmt.Errorf("short stat for %d", pid)
	}
	ppid, _ := strconv.Atoi(fields[1])
	p := proc{pid: pid, ppid: ppid, comm: string(stat[open+1 : close]), start: fields[19]}
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmdline = bytes.TrimRight(cmdline, "\x00")
		if len(cmdline) > 0 {
			p.args = strings.Split(string(cmdline), "\x00")
		}
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		p.cwd = cwd
	}
	return p, nil
}
