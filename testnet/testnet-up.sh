#!/usr/bin/env bash
set -Eeuo pipefail

# See https://yakking.branchable.com/posts/networking-4-namespaces-and-multi-host-routing/

sudo ip netns add near
sudo ip netns add far

sudo ip link add one type veth peer name two
sudo ip link add three type veth peer name four

sudo ip link set dev two netns near
sudo ip link set dev three netns near
sudo ip link set dev four netns far

sudo ip address add 10.248.1.1/24 dev one
sudo ip netns exec near ip address add 10.248.1.2/24 dev two
sudo ip netns exec near ip address add 10.248.2.1/24 dev three
sudo ip netns exec far ip address add 10.248.2.2/24 dev four
sudo ip netns exec far ip address add 10.248.3.1/24 dev lo

sudo ip link set dev one up
sudo ip netns exec near ip link set dev two up
sudo ip netns exec near ip link set dev three up
sudo ip netns exec far ip link set dev four up
sudo ip netns exec far ip link set dev lo up

sudo ip route add 10.248.2.0/24 dev one via 10.248.1.2
sudo ip route add 10.248.3.0/24 dev one via 10.248.1.2

sudo ip netns exec near ip route change 10.248.1.0/24 dev two via 10.248.1.1
sudo ip netns exec near ip route add 10.248.3.0/24 dev three via 10.248.2.2

sudo ip netns exec far ip route add 10.248.1.0/24 dev four via 10.248.2.1
