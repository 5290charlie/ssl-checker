#!/bin/bash

NAME=ssl-checker
PATH=/usr/local/bin
FILE=$PATH/$NAME
TARGET="$(pwd)/bin/$NAME"

if [[ "$UID" != "0" ]]; then
	echo "Must run as root (sudo)"
	exit
fi

if [ ! -f $TARGET ]; then
	echo "Missing target: $TARGET"
	exit
fi

if [ ! -d $PATH ]; then
	echo "Creating path: $PATH"
	/bin/mkdir -p $PATH
fi

if [ -f $FILE ]; then
	echo "File: $FILE already exists!"
else
	echo "Linking: $FILE -> $TARGET"
	/bin/ln -s $TARGET $FILE
fi

