#!/bin/bash
# dependencies: bash, bsdtar, curl, awk, jq, yq

# exit on any errors
set -eu -o pipefail

# ================
# = inputs
# ================

declare -A _inputs=(
	[src]=''
	[dest]=''
	[strip]=0
	[include]='[]'
	[exclude]='[]'
	[bsdtar_opts]='[]'
	[token]=''
)

declare -A _outputs=(
	[changed]='boolean'
)

check_inputs()
{
	if [[ -z ${SRC:-} ]]; then fail "'src' unspecified"
	elif [[ -z ${DEST:-} ]]; then fail "'dest' unspecified"
	elif ! isnumber "$STRIP"; then fail "'strip' is not a number"
	fi
}

# ================
# = main
# ================

main()
{
	extract
}

# ================
# = functions
# ================

extract()
{
	local src tmpdest

	case $SRC in
		*://*) src=$SRC ;;
		*) src="file://$SRC" ;;
	esac

	tmpdest=$(mktempfn --directory)

	request "$SRC" |
		bsdtar --file=- --extract \
		--directory="$tmpdest" \
		--strip-components="$STRIP" \
		"${INCLUDE[@]/#/'--include='}" \
		"${EXCLUDE[@]/#/'--exclude='}" \
		"${BSDTAR_OPTS[@]}"

	if diff --recursive --no-dereference --brief "$tmpdest" "$DEST"; then
		CHANGED=false
		succeed "'dest' is already up to date"
	else
		[[ -n ${OWNER:-} ]] && chown --recursive "$OWNER" "$tmpdest"/*
		[[ -n ${GROUP:-} ]] && chown --recursive ":$GROUP" "$tmpdest"/*
		[[ -n ${MODE:-}  ]] && chmod --recursive "$MODE" "$tmpdest"/*
		cp -rf "$tmpdest"/* -t "$DEST"
		CHANGED=true
		succeed "extracted the archive to 'dest'"
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

isnumber()
{
	[ "$1" -eq "$1" ] 2>/dev/null
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
