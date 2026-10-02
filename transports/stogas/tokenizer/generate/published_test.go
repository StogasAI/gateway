package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

func TestWholeWordShortcutRequiresReachableMerge(t *testing.T) {
	// bc merges first. abc exists, but its only rule requires ab+c, so
	// encoding abc must produce a+bc, not take a vocabulary shortcut.
	for _, ignore := range []string{"false", "true"} {
		data := []byte(`{"model":{"type":"BPE","ignore_merges":` + ignore + `,"vocab":{"a":0,"b":1,"c":2,"ab":3,"bc":4,"abc":5},"merges":[["b","c"],["a","b"],["ab","c"]]}}`)
		scanner := bufio.NewScanner(bytes.NewReader(convertPublished(data, false)))
		found := false
		for scanner.Scan() {
			word, value, _ := strings.Cut(scanner.Text(), " ")
			decoded, _ := base64.StdEncoding.DecodeString(word)
			if string(decoded) != "abc" {
				continue
			}
			found = true
			rank, err := strconv.ParseUint(value, 10, 32)
			if err != nil || (rank&(1<<31) != 0) != (ignore == "false") || rank&^(1<<31) != 3 {
				t.Fatalf("ignore_merges=%s: invalid shortcut flag/rank %d (%v)", ignore, rank, err)
			}
		}
		if !found || scanner.Err() != nil {
			t.Fatal("missing generated word", scanner.Err())
		}
	}
}
