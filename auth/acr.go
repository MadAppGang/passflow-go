package auth

import "strconv"

// ACR is an authentication context class reference: Passflow's assurance level for a token.
type ACR string

// The assurance levels Passflow issues, using the NIST authenticator assurance levels.
const (
	ACRNone ACR = "0"
	AAL1    ACR = "1"
	AAL2    ACR = "2"
	AAL3    ACR = "3"
)

// String returns the wire value.
func (a ACR) String() string {
	return string(a)
}

// Level returns the ordinal value of the level as an exact 64-bit integer. A value that does not
// parse as a base 10 integer, does not fit 64 bits, or is negative is level 0.
func (a ACR) Level() int64 {
	n, err := strconv.ParseInt(string(a), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Satisfies reports whether a meets the required level. A required level that parses to 0 is never
// satisfied, so a check built from a wrong configuration value fails closed.
func (a ACR) Satisfies(min ACR) bool {
	required := min.Level()
	return required != 0 && a.Level() >= required
}
