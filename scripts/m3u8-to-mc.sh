#!/bin/bash
NL=$'\n'
IFS_ORIG=$IFS

function err()
{
    echo "$@" 1>&2
}

function gethash_file()
{
    local H
    H=$( "$HASH" "$1" )
    if [ $? -ne 0 ]; then
	err "Could not calculate hash dighest for '$1'"
    fi

    printf "%s" "$H" | cut -d' ' -f1
}

function gethash_text()
{
    printf "%s" "$1" | "$HASH" - | cut -d' ' -f1
}

IN="$1"
INDIR=$( dirname "$IN" )
if  [ ! -f "$IN" ]; then
	err "Usage: $0 [M3U8] [[HASH]]"
	exit 1
fi
HASH="$2"
if [ -z "$HASH" ]; then
	HASH="sha256sum"
fi

PL=$( cat "$IN" )
IFS=$NL
for L in $PL
do
    IFS=$IFS_ORIG

    printf "%s" "$L" | grep -qe '^#.*'
    if [ $? -eq 0 ]; then
	# CONTROL LINE
	# copy
	printf "%s" "$L"
    else
	# FILE
	if [ ! -f "${INDIR}/${L}" ]; then
	    err "Could not find '${INDIR}/${L}'"
	    exit 1
	fi
	H=$( gethash_file "${INDIR}/${L}" )

	# replace entry with hash digest
	printf "%s" "$H"
    fi
    printf "\n"

    IFS=$NL
done
IFS=$IFS_ORIG
exit 0
