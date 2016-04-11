#!/usr/bin/env bash

assert ()                 #  If condition false,
{                         #+ exit from script
                          #+ with appropriate error message.
  E_PARAM_ERR=98
  E_ASSERT_FAILED=99


  if [ -z "$2" ]          #  Not enough parameters passed
  then                    #+ to assert() function.
    return $E_PARAM_ERR   #  No damage done.
  fi

  message=$2

  if [[ ! $1 ]]
  then
    echo "Assertion failed:  \"$1\", $message"
    return $E_ASSERT_FAILED
  fi  
}
#######################################################################

set -e

export CONTAINER_PROC_INJECT_TARGETS=free:top:uptime:cat:zabbix_agentd:main
export LD_PRELOAD=/tmp/inject.so

assert "`cat /proc/stat|grep cpu|wc -l` = 2" "total number of cpus should be 1"
assert "`cat /proc/cpuinfo|grep processor|wc -l` = 1" "total number of cpus should be 1"
assert "`cat /sys/devices/system/cpu/online` = 0-0" "total number of cpus should be 1"
assert "`uptime|awk '{print $3}'` -lt 1" "container should be up for no more than 1 minute"
assert "`top -b -n1|grep 'KiB Mem'|awk '{print $3}'` = 131072" "total memory known by top should be 128M"

declare $(free -m|awk '/^Mem*/{print "total_mem="$2 " used_mem="$3 " free_mem="$5}')
assert "$total_mem = 128" "total memory known by free should be 128M"
assert "0 -lt $used_mem && $used_mem -lt 128" "used memory known by free should be positive and less than 128M"
assert "0 -lt $free_mem && $free_mem -lt 128" "free memory known by free should be positive and less than 128M"
