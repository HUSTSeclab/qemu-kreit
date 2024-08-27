#!/bin/bash

printf "p (int)&((struct task_struct *)0)->pid\nquit\n" |
  gdb $1 -x "" 2> /dev/null |
  grep "\$1" |
  awk '{print $4}'
