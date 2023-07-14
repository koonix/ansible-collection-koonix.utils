#!/bin/bash
# dependencies: bash, perl, curl, awk, jq, yq

# exit on any errors
set -eu -o pipefail

# ================
# = inputs
# ================

declare -A _inputs=(
	[repo]=''
	[provider]=''
	[instance]=''
	[pattern]='**'
	[method]='special'
	[token]=''
	[test_match]='[]'
	[test_no_match]='[]'
)

declare -A _outputs=(
	[result]='string'
)

prepare_inputs()
{
	METHOD=${METHOD,,}
}

check_inputs()
{
	if [[ -z ${REPO:-} ]]; then
		fail "'repo' unspecified"
	fi
	case $METHOD in
		literal|substring|glob|[eb]regex|pcre|special) ;;
		'') fail "'method' unspecified" ;;
		*) fail "unknown 'method': '$METHOD'" ;;
	esac
}

# ================
# = main
# ================

main()
{
	run_tests
	if RESULT=$(get_version); then
		succeed 'got the version successfully'
	fi
}

# ================
# = functions
# ================

get_version()
{
	case $PROVIDER in
		github) get_version_github ;;
		gitlab|codeberg|dockerhub|sourcehut)
			get_version_paginate "${PROVIDER}_api" ;;
		'') fail "'provider' unspecified" ;;
		*) fail "unknown 'provider': '$PROVIDER'" ;;
	esac
	return $(( ! ! $? ))
}

get_version_paginate()
{
	local fn=$1 page=0 list ver
	while :; do
		(( page++ ))
		list=$("$fn" "$page") || return 1
		while IFS= read -r ver; do
			if match_version "$ver" "$PATTERN"; then
				prnt "$ver"
				return
			fi
		done <<< "$list"
	done
}

get_version_after()
{
	local fn=$1 after list ver
	while :; do
		list=$("$fn" "${after:-}") || return 1
		while IFS= read -r ver; do
			if match_version "$ver" "$PATTERN"; then
				prnt "$ver"
				return
			fi
			after=$ver
		done <<< "$list"
	done
}

get_version_github()
{
	if [[ -n ${TOKEN:-} ]]; then
		get_version_paginate github_api
	else
		get_version_after github_html
	fi
}

github_api()
{
	local page=$1 base='https://api.github.com/repos'
	request \
		"$base/$REPO/tags" \
		--data-urlencode "page=$page" \
		--data-urlencode 'per_page=1000' \
		--header 'X-GitHub-Api-Version: 2022-11-28' \
		| jq --raw-output --exit-status '.[].name'
}

github_html()
{
	local after=${1:-} base='https://github.com'
	local pattern='href="/'"$REPO"'/releases/tag/([^"]+)"'
	pattern=$(slash_escape "$pattern")
	request \
		"$base/$REPO/tags" \
		${after:+--data-urlencode "after=$after"} \
		| perl -ne 'print "$1\n" if /'"$pattern"'/'
}

gitlab_api()
{
	local page=$1 base="https://${INSTANCE:-gitlab.com}/api/v4/projects"
	request \
		"$base/$(urlencode "$REPO")/repository/tags" \
		--data-urlencode "page=$page" \
		--data-urlencode 'per_page=1000' \
		| jq --raw-output --exit-status '.[].name'
}

codeberg_api()
{
	local page=$1 base='https://codeberg.org/api/v1/repos'
	request \
		"$base/$REPO/tags" \
		--data-urlencode "page=$page" \
		--data-urlencode 'page_size=1000' \
		| jq --raw-output --exit-status '.[].name'
}

sourcehut_api()
{
	local page=$1 base='https://sr.ht/api/v1/repos'
	request \
		"$base/$REPO/tags" \
		--data-urlencode "page=$page" \
		--data-urlencode 'page_size=1000' \
		| jq --raw-output --exit-status '.[].name'
}

dockerhub_api()
{
	local page=$1 repo=$REPO base='https://hub.docker.com/v2/repositories'
	[[ $repo == */* ]] || repo=library/$repo
	request \
		"$base/$repo/tags" \
		--data-urlencode "page=$page" \
		--data-urlencode 'page_size=1000' \
		--data-urlencode 'ordering=last_updated' \
		| jq --raw-output --exit-status '.results[].name'
}

run_tests()
{
	local ver
	for ver in "${TEST_MATCH[@]}"; do
		if ! match_version "$ver" "$PATTERN"; then
			fail "test_match failed: $ver"
		fi
	done
	for ver in "${TEST_NO_MATCH[@]}"; do
		if match_version "$ver" "$PATTERN"; then
			fail "test_no_match failed: $ver"
		fi
	done
}

match_version()
{
	local version=$1 pattern=$2
	if [[ $METHOD == special ]]; then
		pattern=${pattern#[vV]}
		pattern=${pattern//'***'/'\E(\.\d+)@ASTERISK@\Q'}
		pattern=${pattern//'**'/'\E(\d+\.)@ASTERISK@\d+\Q'}
		pattern=${pattern//'*'/'\E\d+\Q'}
		pattern=${pattern//'@ASTERISK@'/'*'}
		pattern='^[vV]?\Q'"$pattern"'\E$'
	fi
	if [[ $METHOD == special ]] || [[ $METHOD == pcre ]]; then
		pattern=$(slash_escape "$pattern")
		perl -e 'exit(!($ARGV[0] =~ /'"$pattern"'/))' "$version"
	elif [[ $METHOD == eregex    ]]; then grep -qE "$pattern" <<< "$version"
	elif [[ $METHOD == bregex    ]]; then grep -q "$pattern" <<< "$version"
	elif [[ $METHOD == glob      ]]; then [[ $version == $pattern ]]
	elif [[ $METHOD == substring ]]; then [[ $version == *"$pattern"* ]]
	elif [[ $METHOD == literal   ]]; then [[ $version == "$pattern" ]]
	fi
}

_init_request() { headerfile=$(mktempfn) ;}
request()
{
	local code
	local rlremain rlreset # rate-limit status
	while :; do
		command curl -fsSL --get --request 'GET' --dump-header "$headerfile" \
			${TOKEN:+--header "Authorization: Bearer $TOKEN"} "$@" \
			&& code=$? || code=$?
		[[ $code == 0 ]] && return 0
		rlremain=$(get_header 'x-ratelimit-remaining' "$headerfile" || echo 1)
		rlreset=$(get_header 'x-ratelimit-reset' "$headerfile" || echo "$(( EPOCHSECONDS + 1000 ))")
		(( rlremain > 0 || rlreset - EPOCHSECONDS > 60 )) && return 1
		rsleep "$(( rlreset - EPOCHSECONDS + 1 ))"
	done
}

get_header()
{
	local header=$1 file=$2 value
	value=$(
		awk -v header="$header" -v FS='^[^:]*:\\s*' '
			$1 == header { print $2 }
		' "$file"
	)
	[[ -n "$value" ]] && prnt "$value" || return 1
}

# ================
# = utilities
# ================

exec {_sleepfd}<> <(:)
rsleep() { read -t "$1" -u $_sleepfd ||: ;}

prnt()
{
	printf '%s\n' "$@"
}

mktempfn()
{
	command mktemp --tmpdir="$_ANSIBLE_TMPDIR" "$@"
}

fail()
{
	FAILED=true
	MSG="$*"
	return 1
}

succeed()
{
	FAILED=false
	MSG="$*"
}

urlencode()
{
	local LC_ALL=C
	local i c len=${#1}
	for (( i = 0; i < len; i++ )); do
		c=${1:$i:1}
		case $c in
			[a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
			*) printf '%%%02X' "'$c" ;;
		esac
	done
}

urldecode()
{
	local str=${1//+/ }
	printf '%b' "${str//%/\\x}"
}

slash_escape()
{
	while [[ $pattern == *__BB__* ]]; do
		pattern=${pattern//__BB__/''}
	done
	pattern=${pattern//'\\'/__BB__}
	pattern=${pattern//'\/'/'/'}
	pattern=${pattern//'/'/'\/'}
	pattern=${pattern//__BB__/'\\'}
	prnt "$pattern"
}

# ================
# = output
# ================

trap output EXIT
output()
{
	local var type json

	_outputs[msg]='string'
	_outputs[failed]='boolean'

	[[ -z ${FAILED:-} ]] && FAILED=true
	[[ $FAILED != false ]] && [[ -z ${MSG:-} ]] && return

	json='{'
	for var in "${!_outputs[@]}"; do
		type=${_outputs[$var]}
		var=${var^^}
		if [[ -z ${!var:-} ]]; then
			declare "$var=null"
		elif [[ $type == string ]]; then
			declare "$var=$(jq --null-input --arg str "${!var}" '$str')"
		fi
		json="$json\"${var,,}\":${!var},"
	done
	json="${json%,}}"

	prnt "$json"
}

# ================
# = init outputs
# ================

for var in "${!_outputs[@]}"; do
	unset "${var^^}"
done

# ================
# = read inputs
# ================

_inputs[_ansible_tmpdir]=''

for var in "${!_inputs[@]}"; do
	declare "$var=${_inputs[$var]}"
done

source "$1"

exec {fd}<> <(:)
for var in "${!_inputs[@]}"; do
	if [[ ${_inputs[$var]} == '['*']' ]]; then
		readarray -d $'\0' "${var^^}" < <(
			yq -j 'if type != "array" then [.][] else .[] end | tostring | (.+"\u0000")' <<< "${!var}"
			echo $? >&"$fd"
		)
		read -t 0.1 -u "$fd" ret
		if [[ $ret != 0 ]]; then
			fail 'failed to parse the inputs using `yq`'
		fi
	else
		declare "${var^^}=${!var}"
	fi
done

[[ ! -d $_ANSIBLE_TMPDIR ]] && _ANSIBLE_TMPDIR=${TMPDIR:-/tmp}
command -v prepare_inputs >/dev/null && prepare_inputs
command -v check_inputs   >/dev/null && check_inputs

# ================
# = run _init_*()
# ================

while IFS= read -r fn; do
	[[ $fn == _init_* ]] && "$fn"
done <<< "$(compgen -A function)"

# ================
# = run main
# ================

main "$@"
[[ ${FAILED:-} != false ]] && exit 1

# vim:noexpandtab
