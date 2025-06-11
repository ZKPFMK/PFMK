#!/usr/bin/bash
for((i=3; i<=26; i++));
do
	../linux/bin/pod_dummy --thread_num 1 --disable_tbb --sudoku $i
done
