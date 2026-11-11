package auth_test

import "testing"

// Exercise header order through public Verify, not a private parser.
func TestHeaderInspectionOrder(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool {
		switch row.Expect.Reason {
		case "malformed", "alg", "crit", "kid_missing":
			return true
		default:
			return false
		}
	})
}
