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

# ================
# = main
# ================

main()
{
	# prepare the inputs
	METHOD=${METHOD,,}

	run_tests

	RESULT=$(get_version) && code=$? || code=$?

	case $code in
		0)
			FAILED=false
			MSG="got the version successfully" ;;
		1)
			FAILED=true RESULT=null
			MSG="couldn't get the version" ;;
		2)
			FAILED=true RESULT=null
			MSG="'github' or 'gitlab' or 'dockerhub' needs to be specified" ;;
	esac

	# output
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
		*) return 2 ;;
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
		--url-query "page=$page" \
		--url-query 'per_page=1000' \
		--header 'X-GitHub-Api-Version: 2022-11-28' \
		| jq --raw-output --exit-status '.[].name'
}

github_html()
{
	local after=${1:-} base='https://github.com'
	local pattern='href="/'"$REPO"'/releases/tag/([^"]+)"'
	pattern=${pattern//'/'/'\/'}
	request \
		"$base/$REPO/tags" \
		${after:+--url-query "after=$after"} \
		| perl -ne 'print "$1\n" if /'"$pattern"'/'
}

gitlab_api()
{
	local page=$1 base="https://${INSTANCE:-gitlab.com}/api/v4/projects"
	request \
		"$base/$REPO/repository/tags" \
		--url-query "page=$page" \
		--url-query 'per_page=1000' \
		| jq --raw-output --exit-status '.[].name'
}

codeberg_api()
{
	local page=$1 base='https://codeberg.org/api/v1/repos'
	request \
		"$base/$REPO/tags" \
		--url-query "page=$page" \
		--url-query 'page_size=1000' \
		| jq --raw-output --exit-status '.[].name'
}

sourcehut_api()
{
	local page=$1 base='https://sr.ht/api/v1/repos'
	request \
		"$base/$REPO/tags" \
		--url-query "page=$page" \
		--url-query 'page_size=1000' \
		| jq --raw-output --exit-status '.[].name'
}

dockerhub_api()
{
	local page=$1 repo=$REPO base='https://hub.docker.com/v2/repositories'
	[[ repo == */* ]] || repo=library/$repo
	request \
		"$base/$repo/tags" \
		--url-query "page=$page" \
		--url-query 'page_size=1000' \
		--url-query 'ordering=last_updated' \
		| jq --raw-output --exit-status '.results[].name'
}

run_tests()
{
	local ver
	for ver in "${TEST_MATCH[@]}"; do
		match_version "$ver" "$PATTERN" || die "test_match failed: $ver"
	done
	for ver in "${TEST_NO_MATCH[@]}"; do
		match_version "$ver" "$PATTERN" && die "test_no_match failed: $ver" ||:
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
		pattern=${pattern//'/'/'\/'}
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
		command curl -fsSL --request 'GET' --dump-header "$headerfile" \
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
# = output
# ================

output()
{
	local var type json

	_outputs[msg]='string'
	_outputs[failed]='boolean'

	[[ -z ${FAILED:-} ]] && FAILED=true

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

die()
{
	# MSG="$1"
	# FAILED=true
	# output
	exit 1
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
		[[ $ret != 0 ]] && die 'failed to parse the inputs using `yq`'
	else
		declare "${var^^}=${!var}"
	fi
done

[[ ! -d $_ANSIBLE_TMPDIR ]] && _ANSIBLE_TMPDIR=${TMPDIR:-/tmp}

# ================
# = run inits
# ================

while IFS= read -r fn; do
	[[ $fn == _init_* ]] && "$fn"
done <<< "$(compgen -A function)"

# ================
# = run main
# ================

main "$@"
