#!/usr/bin/env bash

# See https://yakking.branchable.com/posts/networking-4-namespaces-and-multi-host-routing/

set -Eeuo pipefail

sudo ip netns del fw-111
sudo ip netns del as-111
sudo ip netns del fw-112
sudo ip netns del as-112

sudo ip link del one-111
sudo ip link del infra1-111
sudo ip link del one-112
sudo ip link del infra1-112
