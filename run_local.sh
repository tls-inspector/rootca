#!/bin/bash
set -e

cd updater
go build -o rootca
cd ../
mv updater/rootca .
./rootca