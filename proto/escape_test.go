package proto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRFC1738Unescape(t *testing.T) {
	testcases := []struct {
		input  string
		output string
	}{
		{
			"%2Fdata%2Fsource%2Fpath",
			"/data/source/path",
		},
		{
			"http://foo.invalid%2Fdata%2Fsource%2Fpath",
			"http://foo.invalid/data/source/path",
		},
		{
			"w%0Ard",
			"w\nrd",
		},
		{
			"w%rd",
			"w%rd",
		},
		{
			"w%%rd",
			"w%rd",
		},
		{
			"w%%%rd",
			"w%%rd",
		},
		{
			"Bad String %1",
			"Bad String %1",
		},
		{
			"Bad String %1A%3",
			"Bad String \032%3",
		},
		{
			"Good String %1A",
			"Good String \032",
		},
		{
			"w%00rd",
			"w%00rd",
		},
		{
			"w%0rd",
			"w%0rd",
		},
		{
			"w%%00%rd",
			"w%00%rd",
		},
		{
			"w%%%00%rd",
			"w%%00%rd",
		},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("Testcase#%d", i+1), func(t *testing.T) {
			output := RFC1738Unescape([]byte(tc.input))
			if bytes.Compare(output, []byte(tc.output)) != 0 {
				t.Errorf("got: %x, want: %x", output, []byte(tc.output))
			}
		})
	}
}
