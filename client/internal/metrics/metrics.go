// Package metrics measures CPU time (Fabric containers via cgroup v2, processes via /proc) and storage.
package metrics

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ContainerCPU returns cumulative CPU seconds of all containers whose name contains one of the substrings.
func ContainerCPU(subs ...string) (float64, error) {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}").Output()
	if err != nil {
		return 0, err
	}
	var total float64
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		match := false
		for _, s := range subs {
			if strings.Contains(f[1], s) {
				match = true
			}
		}
		if !match {
			continue
		}
		for _, p := range []string{
			"/sys/fs/cgroup/system.slice/docker-" + f[0] + ".scope/cpu.stat",
			"/sys/fs/cgroup/docker/" + f[0] + "/cpu.stat",
		} {
			if b, err := os.ReadFile(p); err == nil {
				for _, line := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(line, "usage_usec ") {
						v, _ := strconv.ParseFloat(strings.TrimPrefix(line, "usage_usec "), 64)
						total += v / 1e6
					}
				}
				break
			}
		}
	}
	return total, nil
}

// ProcCPU returns user+system CPU seconds of a process (clock ticks assumed 100 Hz, as on Linux runners).
func ProcCPU(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	f := strings.Fields(s[i+2:])
	u, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	return (u + st) / 100
}

// SelfCPU returns this process's CPU seconds.
func SelfCPU() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

// DirBytes returns the total size of regular files under dir.
func DirBytes(dir string) int64 {
	var n int64
	filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// VolumeBytes returns the size of a docker volume path inside a container (e.g. a peer's ledger).
func VolumeBytes(container, path string) int64 {
	out, err := exec.Command("docker", "exec", container, "sh", "-c", "du -sb "+path+" 2>/dev/null | cut -f1").Output()
	if err != nil {
		return -1
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return v
}

// CPUModel returns the host CPU model name.
func CPUModel() string {
	b, _ := os.ReadFile("/proc/cpuinfo")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "model name") {
			return strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}
	return "unknown"
}
