//go:build !linux

package agent

import (
	"errors"
	"net"
)

func peerPID(net.Conn) int { return 0 }

func readProc(int) (proc, error) {
	return proc{}, errors.New("process inspection is only implemented on Linux")
}
