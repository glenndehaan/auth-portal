#!/bin/bash

WORKSPACE=$(pwd)
DIRS=( "$WORKSPACE/auth" "$WORKSPACE/web" )

echo ""
echo "--------------------------------------------------------------"
echo "Installing dependencies. Hang on this can take a while...."
echo "--------------------------------------------------------------"
echo ""

for DIR in "${DIRS[@]}"
do
  echo ""
  echo "--------------------------------------------------------------"
  echo "Now installing: $DIR"
  echo "--------------------------------------------------------------"
  echo ""

	cd $DIR
	npm ci
done

echo ""
echo "--------------------------------------------------------------"
echo "Done !!!"
echo "--------------------------------------------------------------"
echo ""
