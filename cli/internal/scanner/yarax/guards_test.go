package yarax

import (
	"strconv"
	"strings"
	"testing"
)

// TestYrScanArgs_SafetyGuards ensures every yr invocation carries the per-file
// safety guards so a pathological file can neither hang nor OOM the scan.
func TestYrScanArgs_SafetyGuards(t *testing.T) {
	args := yrScanArgs("/rules", "/target/blob")
	joined := strings.Join(args, " ")

	for _, want := range []string{"--skip-larger", "--timeout", "--no-mmap", "--output-format", "json"} {
		if !contains(args, want) {
			t.Errorf("yr args missing %q: %v", want, args)
		}
	}
	// --skip-larger carries the byte cap; --timeout carries the seconds.
	if !strings.Contains(joined, strconv.FormatInt(yrSkipLargerBytes, 10)) {
		t.Errorf("expected skip-larger cap %d in args: %v", yrSkipLargerBytes, args)
	}
	if !strings.Contains(joined, strconv.Itoa(yrScanTimeoutSecs)) {
		t.Errorf("expected timeout %d in args: %v", yrScanTimeoutSecs, args)
	}
	// Rules dir and target come last, in order.
	if args[len(args)-2] != "/rules" || args[len(args)-1] != "/target/blob" {
		t.Errorf("expected rulesDir then target at the end, got: %v", args[len(args)-2:])
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
