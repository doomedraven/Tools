#!/bin/bash

if [ ! -f "/usr/local/bin/brew" ]; then
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew install yara
ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future python3 -m pip install yara-python
