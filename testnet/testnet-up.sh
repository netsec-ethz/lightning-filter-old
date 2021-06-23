#!/usr/bin/env bash
set -Eeuo pipefail

# See https://yakking.branchable.com/posts/networking-4-namespaces-and-multi-host-routing/

sudo ip netns add near-0
sudo ip netns add far-0

sudo ip netns add near-1
sudo ip netns add far-1

sudo ip link add one type veth peer name two
sudo ip link add three type veth peer name four

sudo ip link add five type veth peer name six
sudo ip link add seven type veth peer name eight

sudo ip link set dev two netns near-0
sudo ip link set dev three netns near-0
sudo ip link set dev four netns far-0

sudo ip link set dev six netns near-1
sudo ip link set dev seven netns near-1
sudo ip link set dev eight netns far-1

sudo ip address add 10.248.1.1/24 dev one
sudo ip netns exec near-0 ip address add 10.248.1.2/24 dev two
sudo ip netns exec near-0 ip address add 10.248.2.1/24 dev three
sudo ip netns exec far-0 ip address add 10.248.2.2/24 dev four
sudo ip netns exec far-0 ip address add 10.248.3.1/24 dev lo

sudo ip address add 10.248.4.1/24 dev five
sudo ip netns exec near-1 ip address add 10.248.4.2/24 dev six
sudo ip netns exec near-1 ip address add 10.248.5.1/24 dev seven
sudo ip netns exec far-1 ip address add 10.248.5.2/24 dev eight
sudo ip netns exec far-1 ip address add 10.248.6.1/24 dev lo

sudo ip link set dev one up
sudo ip netns exec near-0 ip link set dev two up
sudo ip netns exec near-0 ip link set dev three up
sudo ip netns exec far-0 ip link set dev four up
sudo ip netns exec far-0 ip link set dev lo up

sudo ip link set dev five up
sudo ip netns exec near-1 ip link set dev six up
sudo ip netns exec near-1 ip link set dev seven up
sudo ip netns exec far-1 ip link set dev eight up
sudo ip netns exec far-1 ip link set dev lo up

sudo ip route add 10.248.2.0/24 dev one via 10.248.1.2
sudo ip route add 10.248.3.0/24 dev one via 10.248.1.2

sudo ip route add 10.248.5.0/24 dev five via 10.248.4.2
sudo ip route add 10.248.6.0/24 dev five via 10.248.4.2

sudo ip netns exec near-0 ip route add 10.248.4.0/24 dev two via 10.248.1.1
sudo ip netns exec near-0 ip route add 10.248.5.0/24 dev two via 10.248.1.1
sudo ip netns exec near-0 ip route add 10.248.6.0/24 dev two via 10.248.1.1

sudo ip netns exec near-0 ip route add 10.248.3.0/24 dev three via 10.248.2.2

sudo ip netns exec near-0 ip route change 10.248.1.0/24 dev two via 10.248.1.1
sudo ip netns exec near-0 ip route change 10.248.2.0/24 dev three via 10.248.2.2

sudo ip netns exec far-0 ip route add 10.248.1.0/24 dev four via 10.248.2.1
sudo ip netns exec far-0 ip route add 10.248.4.0/24 dev four via 10.248.2.1
sudo ip netns exec far-0 ip route add 10.248.5.0/24 dev four via 10.248.2.1
sudo ip netns exec far-0 ip route add 10.248.6.0/24 dev four via 10.248.2.1

sudo ip netns exec near-1 ip route add 10.248.1.0/24 dev six via 10.248.4.1
sudo ip netns exec near-1 ip route add 10.248.2.0/24 dev six via 10.248.4.1
sudo ip netns exec near-1 ip route add 10.248.3.0/24 dev six via 10.248.4.1

sudo ip netns exec near-1 ip route add 10.248.6.0/24 dev seven via 10.248.5.2

sudo ip netns exec near-1 ip route change 10.248.4.0/24 dev six via 10.248.4.1
sudo ip netns exec near-1 ip route change 10.248.5.0/24 dev seven via 10.248.5.2

sudo ip netns exec far-1 ip route add 10.248.1.0/24 dev eight via 10.248.5.1
sudo ip netns exec far-1 ip route add 10.248.2.0/24 dev eight via 10.248.5.1
sudo ip netns exec far-1 ip route add 10.248.3.0/24 dev eight via 10.248.5.1
sudo ip netns exec far-1 ip route add 10.248.4.0/24 dev eight via 10.248.5.1
