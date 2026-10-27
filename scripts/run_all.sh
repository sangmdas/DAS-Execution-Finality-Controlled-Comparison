#!/bin/sh
set -eu
mkdir -p reports
python3 -m finality_lab.demo
if python3 -m unittest discover -s tests -v > reports/TEST_RUN.txt 2>&1; then
  cat reports/TEST_RUN.txt
else
  cat reports/TEST_RUN.txt
  exit 1
fi
python3 -m finality_lab.experiments
