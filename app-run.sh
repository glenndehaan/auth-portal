#!/bin/bash

WORKSPACE=$(pwd)

cd $WORKSPACE/api/auth && npm run dev & cd $WORKSPACE/api/web && npm run dev && kill $!
