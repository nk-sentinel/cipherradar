package container

import (
	"reflect"
	"testing"
)

func TestSortedUnique(t *testing.T) {
	cases := []struct {
		in   []int
		want []int
	}{
		{[]int{3, 1, 2, 1, 3}, []int{1, 2, 3}},
		{[]int{1}, []int{1}},
		{nil, nil},
	}
	for _, c := range cases {
		if got := sortedUnique(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("sortedUnique(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
