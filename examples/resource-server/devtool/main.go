// Command devtool creates the testdata the resource-server examples need on a local Passflow and
// issues real tokens through its public HTTP API. See README.md.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultServer = "http://localhost:8765"
	defaultKey    = "test-management-key"
	defaultOut    = ".out"
	browserOrigin = "http://localhost:5173"

	seedFile     = "seed.json"
	manifestFile = "tokens.json"
)

// seedState is what `seed` leaves for `tokens` and for the person running the browser check.
type seedState struct {
	Server     string `json:"server"`
	AppA       string `json:"app_a"`
	AppB       string `json:"app_b"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret"`
}

// manifestEntry describes one token file. scripts/api-check.sh reads these fields.
type manifestEntry struct {
	File     string `json:"file"`
	App      string `json:"app"`
	ACR      string `json:"acr"`
	AuthTime int64  `json:"auth_time"`
	Exp      int64  `json:"exp"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "devtool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: devtool seed|tokens|totp <secret>")
	}
	command, rest := args[0], args[1:]
	switch command {
	case "seed":
		return runSeed(rest)
	case "tokens":
		return runTokens(rest)
	case "totp":
		return runTOTP(rest)
	default:
		return fmt.Errorf("unknown command %q: use seed, tokens or totp", command)
	}
}

func runSeed(args []string) error {
	flags := flag.NewFlagSet("seed", flag.ContinueOnError)
	server := flags.String("server", defaultServer, "Passflow base URL")
	key := flags.String("key", defaultKey, "management key")
	out := flags.String("out", defaultOut, "output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}

	api := newAPI(*server)
	appA, err := api.createApp(*key, "Resource server example, app A")
	if err != nil {
		return fmt.Errorf("create app A: %w", err)
	}
	appB, err := api.createApp(*key, "Resource server example, app B")
	if err != nil {
		return fmt.Errorf("create app B: %w", err)
	}

	suffix, err := randomHex(8)
	if err != nil {
		return err
	}
	state := seedState{
		Server: *server,
		AppA:   appA,
		AppB:   appB,
		Email:  "resource-server-" + suffix + "@example.com",
		// Unique per run, and it satisfies the password policy in passflow.yaml.
		Password: "Example!" + suffix + "aA1",
	}

	session, err := api.register(state.AppA, state.Email, state.Password)
	if err != nil {
		return fmt.Errorf("register the user: %w", err)
	}
	state.TOTPSecret, err = api.enrolTOTP(state.AppA, session.Access)
	if err != nil {
		return fmt.Errorf("enrol TOTP: %w", err)
	}

	if err := writeSeed(*out, state); err != nil {
		return err
	}
	fmt.Printf("app A (VITE_PASSFLOW_APP_ID, PASSFLOW_AUDIENCE): %s\n", state.AppA)
	fmt.Printf("app B: %s\n", state.AppB)
	fmt.Printf("user: %s\n", state.Email)
	fmt.Printf("password: %s\n", state.Password)
	fmt.Printf("TOTP secret: %s\n", state.TOTPSecret)
	fmt.Printf("wrote %s\n", filepath.Join(*out, seedFile))
	return nil
}

func runTokens(args []string) error {
	flags := flag.NewFlagSet("tokens", flag.ContinueOnError)
	server := flags.String("server", "", "Passflow base URL (default: the one seed used)")
	out := flags.String("out", defaultOut, "output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}

	state, err := readSeed(*out)
	if err != nil {
		return err
	}
	if *server != "" {
		state.Server = *server
	}
	api := newAPI(state.Server)

	base, err := api.signIn(state.AppA, state.Email, state.Password)
	if err != nil {
		return fmt.Errorf("sign in on app A: %w", err)
	}
	aal1, err := entryFor("aal1.jwt", state.AppA, base.Access)
	if err != nil {
		return err
	}
	if base.Refresh == "" {
		return errors.New("sign-in on app A returned no refresh token: is the app Offline, and was the offline scope sent?")
	}

	code, err := totpCode(state.TOTPSecret, time.Now())
	if err != nil {
		return err
	}
	upgraded, err := api.upgradeWithTOTP(state.AppA, base.Refresh, code)
	if err != nil {
		return fmt.Errorf("upgrade with TOTP: %w", err)
	}
	aal2, err := entryFor("aal2.jwt", state.AppA, upgraded.Access)
	if err != nil {
		return err
	}
	if aal1.ACR != "1" || aal2.ACR != "2" {
		return fmt.Errorf("expected acr 1 then 2, got %q then %q", aal1.ACR, aal2.ACR)
	}

	other, err := api.signIn(state.AppB, state.Email, state.Password)
	if err != nil {
		return fmt.Errorf("sign in on app B: %w", err)
	}
	wrongAud, err := entryFor("wrong-aud.jwt", state.AppB, other.Access)
	if err != nil {
		return err
	}

	for name, content := range map[string]string{
		aal1.File:      base.Access,
		"aal1.refresh": base.Refresh,
		aal2.File:      upgraded.Access,
		wrongAud.File:  other.Access,
	} {
		if err := writePrivate(*out, name, []byte(content)); err != nil {
			return err
		}
	}
	manifest, err := json.MarshalIndent([]manifestEntry{aal1, aal2, wrongAud}, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivate(*out, manifestFile, append(manifest, '\n')); err != nil {
		return err
	}

	fmt.Printf("wrote aal1.jwt, aal1.refresh, aal2.jwt, wrong-aud.jwt and %s to %s\n", manifestFile, *out)
	fmt.Printf("T0 (auth_time of aal2.jwt): %d\n", aal2.AuthTime)
	return nil
}

func runTOTP(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: devtool totp <secret>")
	}
	code, err := totpCode(args[0], time.Now())
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}

// entryFor reads the manifest fields from a token Passflow just issued. The token is not verified
// here: checking tokens is the job of the examples under test.
func entryFor(file, app, token string) (manifestEntry, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return manifestEntry{}, fmt.Errorf("%s: the server did not return a JWT", file)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return manifestEntry{}, fmt.Errorf("%s: the payload is not base64url", file)
	}
	var claims struct {
		ACR      string  `json:"acr"`
		AuthTime float64 `json:"auth_time"`
		Exp      float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return manifestEntry{}, fmt.Errorf("%s: the payload is not JSON", file)
	}
	return manifestEntry{
		File:     file,
		App:      app,
		ACR:      claims.ACR,
		AuthTime: int64(claims.AuthTime),
		Exp:      int64(claims.Exp),
	}, nil
}

func writeSeed(dir string, state seedState) error {
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(dir, seedFile, append(encoded, '\n'))
}

func readSeed(dir string) (seedState, error) {
	var state seedState
	encoded, err := os.ReadFile(filepath.Join(dir, seedFile))
	if err != nil {
		return state, fmt.Errorf("read the seed: %w (run devtool seed first)", err)
	}
	if err := json.Unmarshal(encoded, &state); err != nil {
		return state, fmt.Errorf("read the seed: %w", err)
	}
	return state, nil
}

// writePrivate writes a file only the current user can read, because these hold credentials.
func writePrivate(dir, name string, content []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), content, 0o600)
}

func randomHex(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
