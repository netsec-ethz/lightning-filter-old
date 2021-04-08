RUN_PATH="$(cd -P "$(dirname "$0")" && pwd -P)"

export LD_LIBRARY_PATH="$RUN_PATH/lib/go"

"$RUN_PATH/build/app/scionfwd" -c 0xFFFF3FFFFFFFF3FFFF -- -r 0x36 -x 0x36 -y 0x36 -n -l -i -K 1 -S 5 -E 750000  -R 10000  -D 2500000

# This is the run-script to run the lightning filter
# to run the application we need to link the key manager library first.
# I found no other way than doing it like this.

# The parameters consists of the following options:
# EAL values:
# -c -- this is the coremask, for more info check out the socket_layout.md file

# other options:
# -r -- receive port mask
# -x -- bypass port mask
# -y -- firewall port mask
# -n -- enable NUMA-aware allocation
# -l -- enable configuration from config_file
# -i -- enable interactive mode through the CLI
# -K -- define the key manager grace period
# -S -- define the interval in which stats are collected
# -E -- define bloom filter expected number of elements
# -R -- define bloom filter false poritive rate
# -D -- define bloom filter roation interval (microseconds)


# Below are other run configs that were used for the evaluation.
# The only thing that changes is the coremask

# 4ports
# ./build/app/scionfwd -c 0xFFFF3FFFFFFFF3FFFF -- -r 0x36 -x 0x36 -t 0x36 -y 0x36 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x000030000FFFF3FFFF -- -r 0x36 -x 0x36 -t 0x36 -y 0x36 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x00003000000FF300FF -- -r 0x36 -x 0x36 -t 0x36 -y 0x36 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x000030000000F3000F -- -r 0x36 -x 0x36 -t 0x36 -y 0x36 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000


# 1 port
# ./build/app/scionfwd -c 0x000000000FFFF0000F -- -r 0x10 -x 0x10 -t 0x10 -y 0x10 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x00000000000FF0000F -- -r 0x10 -x 0x10 -t 0x10 -y 0x10 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x000000000000F0000F -- -r 0x10 -x 0x10 -t 0x10 -y 0x10 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
# ./build/app/scionfwd -c 0x00000000000030000F -- -r 0x10 -x 0x10 -t 0x10 -y 0x10 -n -l -K 15 -S 5 -E 750000  -R 10000  -D 2500000
