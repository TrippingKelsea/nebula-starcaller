package cert

import "testing"

func TestAnyContainsCIDR(t *testing.T) {
	cases := []struct {
		parents []string
		child   string
		want    bool
	}{
		{[]string{"10.0.0.0/8"}, "10.42.0.5/16", true},
		{[]string{"10.0.0.0/8"}, "192.168.1.5/24", false},
		{[]string{"10.0.0.0/8"}, "10.42.0.5", true},
		{[]string{"10.42.0.0/16"}, "10.42.5.10/16", true},
		{[]string{"10.42.0.0/24"}, "10.42.5.10/16", false},
		{[]string{"garbage"}, "10.0.0.0/8", false},
	}
	for _, tc := range cases {
		got := anyContainsCIDR(tc.parents, tc.child)
		if got != tc.want {
			t.Errorf("anyContainsCIDR(%v, %q) = %v; want %v", tc.parents, tc.child, got, tc.want)
		}
	}
}
