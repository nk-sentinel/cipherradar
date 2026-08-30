package container

import (
	"reflect"
	"testing"
)

// TestActualContainerPasses guards the honest-reporting fix (gh #83): container
// mode runs only the Pass-1 equivalent today, so PassesRun must never claim
// Pass 2 or 3 ran, regardless of what was requested.
func TestActualContainerPasses(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want []int
	}{
		{"deep requests all, only pass 1 runs", []int{1, 2, 3}, []int{1}},
		{"default 1,2 -> 1", []int{1, 2}, []int{1}},
		{"pass 1 only", []int{1}, []int{1}},
		{"pass 3 only -> nothing runs", []int{3}, nil},
		{"pass 2,3 -> nothing runs", []int{2, 3}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := actualContainerPasses(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("actualContainerPasses(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
