//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// childrenRSS sums the resident memory of every descendant process (WebKitGTK runs its pages in
// WebKitWebProcess children), or -1 if /proc cannot be read.
func childrenRSS() int64 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	parent := map[int]int{}
	rss := map[int]int64{}
	page := int64(os.Getpagesize())
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ... ; comm may contain spaces, so split after the last ')'.
		s := string(stat)
		f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
		if len(f) < 22 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		pages, _ := strconv.ParseInt(f[21], 10, 64)
		parent[pid], rss[pid] = ppid, pages*page
	}
	self := os.Getpid()
	var total int64
	for pid := range parent {
		for p, depth := parent[pid], 0; p > 1 && depth < 16; p, depth = parent[p], depth+1 {
			if p == self {
				total += rss[pid]
				break
			}
		}
	}
	return total
}
