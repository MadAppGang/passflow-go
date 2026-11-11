package auth

// SetVerifyHook is the explicitly declared external-test seam.
// Counts bind the verification budget declared in the composition corpus; no private state is read.
func SetVerifyHook(v *Verifier, fn func()) {
	v.verifyHook = fn
}
