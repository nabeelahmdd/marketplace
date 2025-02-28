#!/bin/bash
autoflake --remove-all-unused-imports --in-place "$1" && isort "$1"
