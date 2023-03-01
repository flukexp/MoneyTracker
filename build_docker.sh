#!/bin/sh
app="moneytracker"
docker build -t ${app} .
docker run -p 56733:8000 -d \
  --name=${app} \
  -v $PWD:/app ${app}
