#!/bin/env bash
BUILD=$1

if [ -z "$BUILD" ]; then
  echo "Fournir la version"
  exit 1
fi

mkdir -p build/

zip -r build/mgtransfertool_$BUILD.zip tksample1 bin requirements.txt
