#!/bin/bash
# Banchmark script for cleos command
# usage:
#      bm_cleos_cmd.sh "<cleos_command>" N-iterations

script_name="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
sleep_time=3

print_help() {
    echo "Usage:"
    echo -e "    ${script_name} <command> N-iterations\n"
}

if [[ $# -lt 2 ]]; then
    echo "Error: invalid number of arguments!" >&2
    print_help
    exit 1
fi

command=$1
iterations=$2

re='^[0-9]+$'
if ! [[ $iterations =~ $re ]] ; then
   echo "Error: iteration argument is not a number!" >&2
   print_help
   exit 1;
fi

sum_cpu_usage_us=0
for (( i = 0; i < $iterations; i++ ))
do
    result=$($command -j)
    rc=$?; if [[ $rc != 0 ]]; then echo -e "Error: An error occored while executing command!\n${result}"; exit $rc; fi
    cpu_usage_us=$(echo $result | jq -r ".processed.receipt.cpu_usage_us")
    if [ "$cpu_usage_us" != "<unknown>" ]; then
        sum_cpu_usage_us=$(expr $sum_cpu_usage_us + $cpu_usage_us)
    fi
    sleep $sleep_time
done;

echo "avg. CPU usage: $(expr $sum_cpu_usage_us / $iterations)us"
