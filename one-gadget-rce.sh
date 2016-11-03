#!/bin/bash

addr="$(strings -tx $1 | grep /bin/sh | cut -d' ' -f2)"
objdump -M intel -d "$1" | grep -C8 "$addr"
