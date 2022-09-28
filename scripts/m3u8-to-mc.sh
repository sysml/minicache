#!/bin/bash

#
# MiniCache Tools
#
# Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
#
#
# Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#

NL=$'\n'
IFS_ORIG=$IFS
HASH_INDICATOR_PREFIX='?'

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
	printf "%s%s" "$L" "$NL"
    else
	# FILE
	if [ ! -f "${INDIR}/${L}" ]; then
	    err "Could not find '${INDIR}/${L}'"
	    exit 1
	fi
	H=$( gethash_file "${INDIR}/${L}" )

	# replace entry with hash digest
	printf "%s%s%s" "$HASH_INDICATOR_PREFIX" "$H" "$NL"
    fi

    IFS=$NL
done
IFS=$IFS_ORIG
exit 0
