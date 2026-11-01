package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1, as Passflow does.
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	headerClientID = "X-Passflow-ClientID"
	headerKey      = "X-Passflow-Key"

	totpPeriodSeconds = 30
	totpModulus       = 1_000_000

	maxErrorBody = 500

	// appTemplate has the settings the validation depends on: Offline issues refresh tokens, and
	// the disabled 2FA policy keeps a password sign-in at AAL1 while upgrades still work. A web app
	// sends no request signature, so the browser can use it.
	appTemplate = `{
  "name": "%s",
  "active": true,
  "offline": true,
  "type": "web",
  "redirect_urls": ["%s"],
  "origins": ["%s"],
  "registration_allowed": true,
  "default_scopes": ["id", "offline"],
  "create_tenant_on_registration": "always",
  "two_factor_settings": {"policy": "disabled"},
  "auth_strategies": [
    {"type": "internal", "strategy": {"identity": "email", "challenge": "password", "transport": "none"}}
  ]
}`
	registerTemplate = `{"user":{"email":"%s","password":"%s"},"create_tenant":true,"scopes":["offline","id"]}`
	signInTemplate   = `{"email":"%s","password":"%s","scopes":["offline","id"]}`
	upgradeTemplate  = `{"upgrade":{"type":"totp","assertion":{"code":"%s"}}}`
	confirmTemplate  = `{"code":"%s"}`
)

// api calls the public HTTP API of one Passflow server.
type api struct {
	baseURL string
	client  *http.Client
}

// tokenPair is the part of a token response devtool uses.
type tokenPair struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func newAPI(baseURL string) *api {
	return &api{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *api) createApp(managementKey, name string) (string, error) {
	var created struct {
		ID string `json:"id"`
	}
	body := fmt.Sprintf(appTemplate, name, browserOrigin, browserOrigin)
	headers := map[string]string{headerKey: managementKey}
	if err := a.post("/management/apps", headers, body, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		return "", errors.New("the response had no app ID")
	}
	return created.ID, nil
}

func (a *api) register(appID, email, password string) (tokenPair, error) {
	var tokens tokenPair
	body := fmt.Sprintf(registerTemplate, email, password)
	err := a.post("/auth/register", map[string]string{headerClientID: appID}, body, &tokens)
	return tokens, err
}

func (a *api) signIn(appID, email, password string) (tokenPair, error) {
	var tokens tokenPair
	body := fmt.Sprintf(signInTemplate, email, password)
	err := a.post("/auth/login", map[string]string{headerClientID: appID}, body, &tokens)
	return tokens, err
}

// enrolTOTP enrols TOTP through the v1 setup endpoints, which take no app policy, and returns the
// secret.
func (a *api) enrolTOTP(appID, accessToken string) (string, error) {
	headers := map[string]string{
		headerClientID:  appID,
		"Authorization": "Bearer " + accessToken,
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := a.post("/user/2fa/setup/begin", headers, "", &setup); err != nil {
		return "", err
	}
	if setup.Secret == "" {
		return "", errors.New("the response had no TOTP secret")
	}
	code, err := totpCode(setup.Secret, time.Now())
	if err != nil {
		return "", err
	}
	if err := a.post("/user/2fa/setup/confirm", headers, fmt.Sprintf(confirmTemplate, code), nil); err != nil {
		return "", err
	}
	return setup.Secret, nil
}

func (a *api) upgradeWithTOTP(appID, refreshToken, code string) (tokenPair, error) {
	var tokens tokenPair
	headers := map[string]string{
		headerClientID:  appID,
		"Authorization": "Bearer " + refreshToken,
	}
	err := a.post("/auth/refresh", headers, fmt.Sprintf(upgradeTemplate, code), &tokens)
	return tokens, err
}

// post sends a JSON body and decodes a JSON answer into out, when out is not nil. An error holds the
// path, the status and the server's answer, and never a request header or body.
func (a *api) post(path string, headers map[string]string, body string, out any) error {
	req, err := http.NewRequest(http.MethodPost, a.baseURL+path, bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("POST %s: read the answer: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, truncate(answer))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("POST %s: decode the answer: %w", path, err)
	}
	return nil
}

func truncate(answer []byte) string {
	if len(answer) > maxErrorBody {
		return string(answer[:maxErrorBody]) + "..."
	}
	return string(answer)
}

// totpCode is RFC 6238 with the parameters Passflow uses: HMAC-SHA1, 30 seconds, 6 digits.
func totpCode(secret string, now time.Time) (string, error) {
	normalized := strings.ToUpper(strings.TrimRight(strings.TrimSpace(secret), "="))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", errors.New("the TOTP secret is not base32")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix())/totpPeriodSeconds)

	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%totpModulus), nil
}
