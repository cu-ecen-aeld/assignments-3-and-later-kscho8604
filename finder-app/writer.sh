#!/bin/sh

if [ $# -lt 2 ]
then
    echo "$0 writefile writestr"
    exit 1
else
    writefile=$1
    writestr=$2
fi

path=$(dirname "$writefile")

if [ ! -f $path ]
then
    mkdir -p $path
fi 

echo $writestr > $writefile

