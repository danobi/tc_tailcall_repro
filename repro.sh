#!/bin/bash
#
# Please run `make` before this script.
#
# Usage: ./repro.sh

set -eux

function cleanup {
	tc qdisc del dev lo clsact
}

if [[ $EUID -ne 0 ]]; then
    >&2 echo "Must be run as root"
    exit 1
fi

# Bring loopback up if not
ip link show lo | grep -q 'state UP' || ip link set lo up

# Check that nothing is attached to loopback so far
if bpftool net show dev lo | grep "clsact/ingress"; then
	>&2 echo Something is already attached to lo
	exit 1
fi

# Start driver in background and wait for attachment
./a.out &
trap cleanup EXIT
driver=$!
sleep 1

# Should succeed
ping localhost -W 1 -c 1

# Killing the driver causes all tailcalls to fail closed
kill "$driver"

# This ping should fail now b/c of the above fail-closed behavior
ping localhost -W 1 -c 1
