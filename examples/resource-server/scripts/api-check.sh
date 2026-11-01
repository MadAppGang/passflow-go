#!/usr/bin/env bash
# Black-box check of the example APIs with real Passflow-issued tokens: the A
# rows of the checks in ../README.md. Logs never hold a reusable credential.
#
#   api-check.sh [--lang go|node|all] [--tokens DIR] [--out DIR]
#       A1, A2, A3-tampered, A4, A5, A7, A8 and A10-aud against the running API,
#       then starts its own short-lived instances for A10-iss (port 8091),
#       A6 (FRESH_MAX_AGE=10, port 8092) and A9 (EXPOSE_CHALLENGE_HEADER=false,
#       port 8093). A6 waits until 12 s after the aal2.jwt auth_time.
#
#   api-check.sh --only A3-expired [--lang go|node|all] [--tokens DIR] [--out DIR]
#       Sleeps until exp + 35 s of aal1.jwt, then sends one request per API.
#       No knob shortens a token's life, so this step is scheduled, not inferred.
#
#   api-check.sh --result [--out DIR] [--tokens DIR]
#       Writes DIR/result.md from the recorded rows. Exits 0 only on a full PASS.
#
# Files: --tokens DIR (default examples/resource-server/devtool/.out) holds
# aal1.jwt, aal2.jwt, wrong-aud.jwt and tokens.json from `devtool tokens`.
# --out DIR (default ./validation) receives
# api-<lang>.log (redacted, appended), api-<lang>.tsv (one row per check, replaced
# on re-run) and result.md. --result also reads, when present, tab-separated:
#   browser-<lang>.tsv  B-expose-on|B-transfers-fresh|B-expose-off <TAB> PASS|FAIL <TAB> detail
#   suites.tsv          suite <TAB> PASS|FAIL <TAB> detail
#   skipped.tsv         item <TAB> reason
#
# Environment, with defaults:
#   API_URL_GO=http://localhost:8081            API_URL_NODE=http://localhost:8082
#   API_CMD_GO="go -C examples/resource-server/go-chi run ."
#   API_CMD_NODE="pnpm -C examples/resource-server/node-express start"
#   ALLOWED_ORIGIN=http://localhost:5173        PASSFLOW_ISSUER=http://localhost:8765
#   PASSFLOW_AUDIENCE=the app of aal2.jwt in tokens.json
#
# Needs curl and jq. The API under test must already run with its default settings.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)

ORIGIN=${ALLOWED_ORIGIN:-http://localhost:5173}
ISSUER=${PASSFLOW_ISSUER:-http://localhost:8765}
WRONG_ISSUER=http://127.0.0.1:8765
EXPIRY_MARGIN=35 # the verifiers' 30 s leeway + 5 s
STALE_WAIT=12
STALE_MAX_AGE=10
DEFAULT_MAX_AGE=300
INSTANCE_START_TIMEOUT=180

BEARER_INVALID='Bearer error="invalid_token"'
STEP_UP='Bearer error="insufficient_user_authentication"'

ALL_ROWS="A1 A2 A3-tampered A3-expired A4 A5 A6 A7 A8 A9 A10-aud A10-iss"
BROWSER_ROWS="B-expose-on B-transfers-fresh B-expose-off"

langs="go node"
out_dir=./validation
tokens_dir=$REPO_ROOT/examples/resource-server/devtool/.out
mode=check
any_failure=0
problems=
instance_pid=

work=$(mktemp -d)
chmod 700 "$work"

stop_instance() {
	if [ -n "$instance_pid" ]; then
		kill -TERM -- "-$instance_pid" 2>/dev/null || true
		wait "$instance_pid" 2>/dev/null || true
		instance_pid=
	fi
}

cleanup() {
	stop_instance
	rm -rf "$work"
}
trap cleanup EXIT

die() {
	printf 'api-check: %s\n' "$*" >&2
	exit 2
}

usage() {
	sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"
}

sha8() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -c1-8
	else
		shasum -a 256 | cut -c1-8
	fi
}

iso() {
	date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ
}

# redact_headers replaces the value of every credential-bearing header with a
# short hash, so two requests with the same credential stay correlatable.
redact_headers() {
	local line name value prefix
	local header_re='^([<>] )?([A-Za-z0-9_-]+):[[:space:]]*(.*)$'
	shopt -s nocasematch
	while IFS= read -r line || [ -n "$line" ]; do
		line=${line%$'\r'}
		if [[ $line =~ $header_re ]]; then
			prefix=${BASH_REMATCH[1]}
			name=${BASH_REMATCH[2]}
			value=${BASH_REMATCH[3]}
			case $name in
			access-control-*) ;; # CORS metadata; -credentials here holds no credential
			authorization | proxy-authorization | cookie | set-cookie | x-passflow-* | *-token | *-api-key | api-key | x-auth-* | *-secret | *-credential | *-credentials)
				line="$prefix$name: <redacted sha256:$(printf '%s' "$value" | sha8)>"
				;;
			esac
		fi
		printf '%s\n' "$line"
	done
	shopt -u nocasematch
}

# scrub_jwts is the catch-all for a token outside a header, such as in a body.
scrub_jwts() {
	sed -E 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?/<redacted jwt>/g'
}

# assert_no_credentials empties a file holding a token verbatim and stops the run.
assert_no_credentials() {
	local file=$1 credentials=$work/credentials
	[ -f "$file" ] || return 0
	: >"$credentials"
	local source_file
	for source_file in "$tokens_dir"/*.jwt "$tokens_dir"/*.refresh "$work"/*.jwt; do
		if [ -s "$source_file" ]; then
			cat "$source_file" >>"$credentials"
			printf '\n' >>"$credentials"
		fi
	done
	[ -s "$credentials" ] || return 0
	if grep -qF -f "$credentials" "$file"; then
		: >"$file"
		die "a credential reached $file; the file was emptied"
	fi
}

api_url() {
	case $1 in
	go) printf '%s' "${API_URL_GO:-http://localhost:8081}" ;;
	node) printf '%s' "${API_URL_NODE:-http://localhost:8082}" ;;
	esac
}

api_cmd() {
	case $1 in
	go) printf '%s' "${API_CMD_GO:-go -C examples/resource-server/go-chi run .}" ;;
	node) printf '%s' "${API_CMD_NODE:-pnpm -C examples/resource-server/node-express start}" ;;
	esac
}

# manifest_field <file> <field> reads one field of a tokens.json entry.
manifest_field() {
	jq -er --arg file "$1" --arg field "$2" \
		'(if type == "array" then . else .tokens end) | map(select(.file == $file))[0][$field]' \
		"$tokens_dir/tokens.json" ||
		die "tokens.json has no $2 for $1; run devtool tokens"
}

require_tokens() {
	command -v jq >/dev/null 2>&1 || die "jq is required"
	command -v curl >/dev/null 2>&1 || die "curl is required"
	[ -f "$tokens_dir/tokens.json" ] || die "$tokens_dir/tokens.json not found; run devtool tokens or pass --tokens"
	local file
	for file in aal1.jwt aal2.jwt wrong-aud.jwt; do
		[ -s "$tokens_dir/$file" ] || die "$tokens_dir/$file not found; run devtool tokens or pass --tokens"
	done
}

# write_tampered flips the first signature character. The last one will not do:
# its low bits can be padding, which leaves the decoded signature unchanged.
write_tampered() {
	local token head signature first replacement
	token=$(cat "$tokens_dir/aal2.jwt")
	head=${token%.*}
	signature=${token##*.}
	first=${signature:0:1}
	if [ "$first" = A ]; then replacement=B; else replacement=A; fi
	printf '%s.%s%s' "$head" "$replacement" "${signature:1}" >"$work/tampered.jwt"
}

# send <label> <method> <url> <token-file|-> [header...] makes one request and
# leaves the response in R_* and in $work/hdr and $work/body.
send() {
	local label=$1 method=$2 url=$3 token_file=$4
	shift 4
	local args=(-sS -v --max-time 20 -X "$method" -D "$work/hdr" -o "$work/body" -w '%{http_code}')
	local header token_note=none
	for header in "$@"; do
		args+=(-H "$header")
	done
	: >"$work/hdr"
	: >"$work/body"
	if [ "$token_file" != - ]; then
		# From a file: the token stays out of the process list.
		printf 'Authorization: Bearer %s\n' "$(cat "$token_file")" >"$work/auth"
		args+=(-H "@$work/auth")
		token_note=$(basename "$token_file")
	fi
	R_AT=$(date +%s)
	R_STATUS=$(curl "${args[@]}" "$url" 2>"$work/trace") || R_STATUS=000
	{
		printf '\n=== %s: %s %s token=%s at %s\n' "$label" "$method" "$url" "$token_note" "$(iso "$R_AT")"
		redact_headers <"$work/trace"
		if [ -s "$work/body" ]; then
			printf -- '--- body\n'
			head -c 2048 "$work/body"
			printf '\n'
		fi
	} | scrub_jwts >>"$log_file"
	rm -f "$work/auth"
	assert_no_credentials "$log_file"
	R_WWW=$(header_values www-authenticate | sed -n 1p)
	R_WWW_COUNT=$(header_values www-authenticate | wc -l | tr -d ' ')
	R_CC=$(header_values cache-control | sed -n 1p)
	R_ACAO=$(header_values access-control-allow-origin | sed -n 1p)
	R_ACEH=$(header_values access-control-expose-headers | paste -s -d , -)
}

# header_values prints the value bytes of a response header, one line per field.
header_values() {
	tr -d '\r' <"$work/hdr" | { grep -i "^$1:" || true; } | sed -E 's/^[^:]+: ?//'
}

names_www_authenticate() {
	local names
	names=$(printf '%s' "$1" | tr ',' '\n' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
	grep -qix 'www-authenticate' <<<"$names"
}

problem() {
	problems="${problems:+$problems; }$*"
}

expect_status() {
	[ "$R_STATUS" = "$1" ] || problem "status $R_STATUS, want $1"
}

expect_rejection() {
	expect_status 401
	if [ "$R_WWW_COUNT" != 1 ] || [ "$R_WWW" != "$1" ]; then
		problem "WWW-Authenticate [$R_WWW] x$R_WWW_COUNT, want [$1]"
	fi
	[ "$R_CC" = no-store ] || problem "Cache-Control [$R_CC], want [no-store]"
	[ ! -s "$work/body" ] || problem "the body is not empty"
}

# finish <row> [detail] records the row. problems holds what the expects found.
finish() {
	local row=$1 detail=${2:-} verdict=PASS
	if [ -n "$problems" ]; then
		verdict=FAIL
		any_failure=1
		detail="${detail:+$detail; }$problems"
	fi
	record_row "$row" "$R_STATUS" "$R_WWW" "$R_CC" "$verdict" "$detail"
	problems=
}

record_row() {
	local row=$1 status=$2 www=$3 cc=$4 verdict=$5 detail=$6
	printf '%-5s %-12s %s %s\n' "$verdict" "$row" "$status" "${detail:-$www}"
	if [ -f "$rows_file" ]; then
		{ grep -v "^$row"$'\t' "$rows_file" || true; } >"$work/rows"
	else
		: >"$work/rows"
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$row" "$status" "${www:--}" "${cc:--}" "$verdict" "${detail:--}" >>"$work/rows"
	cat "$work/rows" >"$rows_file"
	assert_no_credentials "$rows_file"
}

fail_row() {
	any_failure=1
	record_row "$1" 000 - - FAIL "$2"
}

# start_instance <name> <port> [VAR=value...] starts the API with extra settings
# in its own process group, so that stopping it also stops what `go run` spawned.
start_instance() {
	local name=$1 port=$2
	shift 2
	instance_url=http://localhost:$port
	if curl -s -o /dev/null --max-time 2 "$instance_url/public"; then
		die "port $port already answers; stop that process, or this check would test it instead"
	fi
	local output=$work/instance-$name.log command
	command=$(api_cmd "$api")
	set -m
	(
		cd "$REPO_ROOT"
		exec env "PORT=$port" "PASSFLOW_ISSUER=$ISSUER" "PASSFLOW_AUDIENCE=$audience" "$@" sh -c "$command"
	) </dev/null >"$output" 2>&1 &
	instance_pid=$!
	set +m
	local deadline=$(($(date +%s) + INSTANCE_START_TIMEOUT))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		if curl -sf -o /dev/null --max-time 2 "$instance_url/public"; then
			return 0
		fi
		if ! kill -0 "$instance_pid" 2>/dev/null; then
			break
		fi
		sleep 1
	done
	printf 'api-check: instance %s did not start. Last output:\n' "$name" >&2
	tail -n 20 "$output" | redact_headers | scrub_jwts >&2
	stop_instance
	return 1
}

check_cors() { # <base-url> <row>: the shared part of A8 and A9
	send "$2 preflight" OPTIONS "$1/invoices" - \
		"Origin: $ORIGIN" \
		"Access-Control-Request-Method: GET" \
		"Access-Control-Request-Headers: authorization"
	case $R_STATUS in
	2??) ;;
	*) problem "preflight status $R_STATUS" ;;
	esac
	[ "$R_ACAO" = "$ORIGIN" ] || problem "preflight allow-origin [$R_ACAO], want [$ORIGIN]"
	local preflight_status=$R_STATUS
	send "$2 actual" GET "$1/invoices" - "Origin: $ORIGIN"
	expect_status 401
	[ "$R_ACAO" = "$ORIGIN" ] || problem "actual allow-origin [$R_ACAO], want [$ORIGIN]"
	R_STATUS="$preflight_status/$R_STATUS"
}

run_primary_checks() {
	local url=$1 t0 age
	t0=$(manifest_field aal2.jwt auth_time)

	problems=
	send A1 GET "$url/public" -
	expect_status 200
	finish A1

	send A2 GET "$url/invoices" -
	expect_rejection Bearer
	finish A2

	send A3-tampered GET "$url/invoices" "$work/tampered.jwt"
	expect_rejection "$BEARER_INVALID"
	finish A3-tampered

	send A4 GET "$url/invoices" "$tokens_dir/aal1.jwt"
	expect_rejection "$STEP_UP, acr_values=\"2\""
	finish A4

	send A5 GET "$url/invoices" "$tokens_dir/aal2.jwt"
	expect_status 200
	finish A5

	send A7 POST "$url/transfers" "$tokens_dir/aal2.jwt"
	age=$((R_AT - t0))
	expect_status 200
	if [ "$age" -gt "$DEFAULT_MAX_AGE" ]; then
		problem "aal2.jwt is ${age}s old, past FRESH_MAX_AGE $DEFAULT_MAX_AGE: run devtool tokens again"
	fi
	finish A7 "token age ${age}s"

	check_cors "$url" A8
	names_www_authenticate "$R_ACEH" || problem "Access-Control-Expose-Headers [$R_ACEH] does not name WWW-Authenticate"
	finish A8 "Access-Control-Allow-Origin: $R_ACAO; Access-Control-Expose-Headers: ${R_ACEH:-absent}"

	send A10-aud GET "$url/invoices" "$tokens_dir/wrong-aud.jwt"
	expect_rejection "$BEARER_INVALID"
	finish A10-aud
}

run_instance_checks() {
	local t0 wake now
	t0=$(manifest_field aal2.jwt auth_time)

	if start_instance a10-iss 8091 \
		"PASSFLOW_ISSUER=$WRONG_ISSUER" \
		"PASSFLOW_JWKS_URL=$ISSUER/.well-known/jwks.json"; then
		send A10-iss GET "$instance_url/invoices" "$tokens_dir/aal2.jwt"
		expect_rejection "$BEARER_INVALID"
		finish A10-iss "instance issuer $WRONG_ISSUER"
		stop_instance
	else
		fail_row A10-iss "the instance did not start"
	fi

	if start_instance a9 8093 EXPOSE_CHALLENGE_HEADER=false; then
		check_cors "$instance_url" A9
		if names_www_authenticate "$R_ACEH"; then
			problem "Access-Control-Expose-Headers [$R_ACEH] names WWW-Authenticate with expose OFF"
		fi
		finish A9 "Access-Control-Allow-Origin: $R_ACAO; Access-Control-Expose-Headers: ${R_ACEH:-absent}"
		stop_instance
	else
		fail_row A9 "the instance did not start"
	fi

	if start_instance a6 8092 "FRESH_MAX_AGE=$STALE_MAX_AGE"; then
		wake=$((t0 + STALE_WAIT))
		now=$(date +%s)
		if [ "$now" -lt "$wake" ]; then
			printf 'waiting %ss until auth_time + %ss\n' "$((wake - now))" "$STALE_WAIT"
			sleep "$((wake - now))"
		fi
		send A6 POST "$instance_url/transfers" "$tokens_dir/aal2.jwt"
		expect_rejection "$STEP_UP, max_age=$STALE_MAX_AGE"
		finish A6 "auth_time $(iso "$t0"); request $(iso "$R_AT"); age $((R_AT - t0))s"
		stop_instance
	else
		fail_row A6 "the instance did not start"
	fi
}

prepare_api() {
	api=$1
	log_file=$out_dir/api-$api.log
	rows_file=$out_dir/api-$api.tsv
	audience=${PASSFLOW_AUDIENCE:-$(manifest_field aal2.jwt app)}
	touch "$log_file"
}

run_checks() {
	local url
	for api in $langs; do
		prepare_api "$api"
		url=$(api_url "$api")
		printf '\n== %s API at %s\n' "$api" "$url"
		if ! curl -s -o /dev/null --max-time 5 "$url/public"; then
			die "$url is not answering; start the $api example with its default settings first"
		fi
		run_primary_checks "$url"
		run_instance_checks
		printf 'A3-expired is a separate, scheduled step: api-check.sh --only A3-expired\n'
	done
}

run_expired() {
	local exp wake now url
	exp=$(manifest_field aal1.jwt exp)
	wake=$((exp + EXPIRY_MARGIN))
	now=$(date +%s)
	if [ "$now" -lt "$wake" ]; then
		printf 'aal1.jwt exp is %s; waiting %ss until exp + %ss\n' "$(iso "$exp")" "$((wake - now))" "$EXPIRY_MARGIN"
		sleep "$((wake - now))"
	fi
	for api in $langs; do
		prepare_api "$api"
		url=$(api_url "$api")
		problems=
		send A3-expired GET "$url/invoices" "$tokens_dir/aal1.jwt"
		expect_rejection "$BEARER_INVALID"
		[ "$R_AT" -ge "$wake" ] || problem "sent before exp + ${EXPIRY_MARGIN}s"
		finish A3-expired "exp $(iso "$exp"); request $(iso "$R_AT")"
	done
}

md_cell() {
	if [ "$1" = - ] || [ -z "$1" ]; then
		printf ' '
	else
		printf '%s' "$1" | sed 's/|/\\|/g'
	fi
}

# shellcheck disable=SC2016 # the backticks are Markdown
md_code() {
	if [ "$1" != - ] && [ -n "$1" ]; then
		printf '`%s`' "$(md_cell "$1")"
	fi
}

# note_outcome folds one row into the overall verdict: FAIL beats anything missing.
note_outcome() {
	case $1 in
	PASS) ;;
	FAIL) verdict=FAIL ;;
	*) if [ "$verdict" = PASS ]; then verdict=INCOMPLETE; fi ;;
	esac
}

note_not_run() {
	printf '| %s | no result recorded |\n' "$1" >>"$work/not-run"
	note_outcome "NOT RUN"
}

# shellcheck disable=SC2016 # the backticks in these printf formats are Markdown
write_api_section() {
	local lang=$1 row status www cc outcome detail
	local rows=$out_dir/api-$lang.tsv
	printf '\n## API checks: %s\n\n' "$lang"
	printf '| Check | Status | WWW-Authenticate | Cache-Control | Result | Detail |\n'
	printf '|---|---|---|---|---|---|\n'
	for row in $ALL_ROWS; do
		if [ -f "$rows" ] && grep -q "^$row"$'\t' "$rows"; then
			IFS=$'\t' read -r _ status www cc outcome detail < <(grep "^$row"$'\t' "$rows" | tail -n 1)
			note_outcome "$outcome"
			printf '| %s | %s | %s | %s | %s | %s |\n' \
				"$row" "$status" "$(md_code "$www")" "$(md_code "$cc")" "$outcome" "$(md_cell "$detail")"
		else
			note_not_run "$lang $row"
			printf '| %s | | | | NOT RUN | |\n' "$row"
		fi
	done
	printf '\nLog: `api-%s.log`\n' "$lang"
}

# shellcheck disable=SC2016 # the backticks in these printf formats are Markdown
write_browser_section() {
	local lang=$1 row outcome detail file
	local rows=$out_dir/browser-$lang.tsv
	printf '\n## Browser round trip: %s\n\n' "$lang"
	printf '| Row | Result | Detail |\n|---|---|---|\n'
	for row in $BROWSER_ROWS; do
		if [ -f "$rows" ] && grep -q "^$row"$'\t' "$rows"; then
			IFS=$'\t' read -r _ outcome detail < <(grep "^$row"$'\t' "$rows" | tail -n 1)
			note_outcome "$outcome"
			printf '| %s | %s | %s |\n' "$row" "$outcome" "$(md_cell "${detail:-}")"
		else
			note_not_run "$lang $row"
			printf '| %s | NOT RUN | |\n' "$row"
		fi
	done
	printf '\nEvidence:\n'
	local found=0
	for file in "$out_dir"/browser-"$lang"-*.png "$out_dir"/console-"$lang".log; do
		if [ -e "$file" ]; then
			printf -- '- `%s`\n' "$(basename "$file")"
			found=1
		fi
	done
	if [ "$found" = 0 ]; then
		printf -- '- none recorded\n'
	fi
}

write_suites_section() {
	local suites=$out_dir/suites.tsv suite outcome detail
	printf '\n## Contract suites\n\n'
	printf '| Suite | Result | Detail |\n|---|---|---|\n'
	if [ -s "$suites" ]; then
		while IFS=$'\t' read -r suite outcome detail || [ -n "$suite" ]; do
			[ -n "$suite" ] || continue
			note_outcome "$outcome"
			printf '| %s | %s | %s |\n' "$suite" "$outcome" "$(md_cell "${detail:-}")"
		done <"$suites"
	else
		note_not_run "contract suites"
		printf '| all | NOT RUN | |\n'
	fi
}

write_result() {
	local result=$out_dir/result.md body=$work/result-body item reason lang
	verdict=PASS
	: >"$work/not-run"
	{
		for lang in go node; do
			write_api_section "$lang"
			write_browser_section "$lang"
		done
		write_suites_section
	} >"$body"
	{
		printf '# Validation result\n\n'
		printf 'Generated %s.\n\n' "$(iso "$(date +%s)")"
		printf '**Verdict: %s**\n' "$verdict"
		cat "$body"
		printf '\n## Skipped\n\n| Item | Reason |\n|---|---|\n'
		if [ -s "$out_dir/skipped.tsv" ]; then
			while IFS=$'\t' read -r item reason || [ -n "$item" ]; do
				[ -n "$item" ] || continue
				printf '| %s | %s |\n' "$item" "$(md_cell "${reason:-}")"
			done <"$out_dir/skipped.tsv"
		fi
		cat "$work/not-run"
	} | scrub_jwts >"$result"
	assert_no_credentials "$result"
	printf 'wrote %s: %s\n' "$result" "$verdict"
	[ "$verdict" = PASS ]
}

only=
while [ "$#" -gt 0 ]; do
	case $1 in
	--lang)
		[ "$#" -ge 2 ] || die "--lang needs a value"
		case $2 in
		go | node) langs=$2 ;;
		all) langs="go node" ;;
		*) die "unknown --lang: $2" ;;
		esac
		shift 2
		;;
	--tokens)
		[ "$#" -ge 2 ] || die "--tokens needs a directory"
		tokens_dir=$2
		shift 2
		;;
	--out)
		[ "$#" -ge 2 ] || die "--out needs a directory"
		out_dir=$2
		shift 2
		;;
	--only)
		[ "$#" -ge 2 ] || die "--only needs a check name"
		[ "$2" = A3-expired ] || die "--only supports A3-expired"
		only=$2
		shift 2
		;;
	--result)
		mode=result
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown argument: $1 (see --help)" ;;
	esac
done

mkdir -p "$out_dir"

if [ "$mode" = result ]; then
	write_result
	exit $?
fi

require_tokens
write_tampered

if [ "$only" = A3-expired ]; then
	run_expired
else
	run_checks
fi

if [ "$any_failure" != 0 ]; then
	printf '\nat least one check failed; see the rows above and %s\n' "$out_dir"
	exit 1
fi
