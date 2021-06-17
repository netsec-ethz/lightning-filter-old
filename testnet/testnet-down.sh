#!/usr/bin/env bash

# See https://yakking.branchable.com/posts/networking-4-namespaces-and-multi-host-routing/

set -Eeuo pipefail

sudo ip netns del far

sudo ip netns del near

sudo ip link del one
