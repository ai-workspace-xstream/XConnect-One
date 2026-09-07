// Modified for XConnect-One: standalone module imports.
package invite_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/invite"
)

type fixtureCase struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	MobileValid bool   `json:"mobile_valid"`
	CLIDevValid bool   `json:"cli_dev_valid"`
}

func TestCanonicalInviteCompatibilityFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/invite-url-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []fixtureCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name+"/mobile", func(t *testing.T) {
			_, err := invite.Parse(test.URL, false)
			if (err == nil) != test.MobileValid {
				t.Fatalf("valid=%v, err=%v", err == nil, err)
			}
			if err != nil && fault.Code(err) != fault.CodeJoinInviteInvalid {
				t.Fatalf("code=%q", fault.Code(err))
			}
		})
		t.Run(test.Name+"/cli-dev", func(t *testing.T) {
			_, err := invite.Parse(test.URL, true)
			if (err == nil) != test.CLIDevValid {
				t.Fatalf("valid=%v, err=%v", err == nil, err)
			}
		})
	}
}

func TestParseErrorNeverContainsInviteSecret(t *testing.T) {
	secret := "xjt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := invite.Parse("xconnect://join/"+secret+"?controller=http://accounts.example", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" || contains(got, secret) {
		t.Fatalf("unsafe error: %q", got)
	}
}

func contains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
