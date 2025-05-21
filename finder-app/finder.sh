#!/bin/sh

if [ $# -lt 2 ]
then
    echo "$0 filesdir searchstr"
    exit 1
else
    filesdir=$1
    searchstr=$2
fi

if [ ! -d $filesdir ]
then
    echo "$filesdir not found."
    exit 1
fi

X=$(find $filesdir/ -type f | wc -l)
Y=$(grep -r $searchstr $filesdir/* | wc -l)

echo "The number of files are $X and the number of matching lines are $Y"
