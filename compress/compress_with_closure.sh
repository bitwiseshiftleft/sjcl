#!/bin/bash

DIR=`dirname $0`

URL="https://dl.google.com/closure-compiler/compiler-latest.zip"
FILE=`echo $URL | sed 's#.*/##'`
unzip > /dev/null 2> /dev/null
if [ $? -eq 0 ] ; then
  wget -V > /dev/null 2> /dev/null
  if [ $? -eq 0 ] ; then
    pushd . > /dev/null
    cd $DIR
    wget -q -N $URL
    popd > /dev/null
  else
    curl -V > /dev/null 2> /dev/null
    if [ $? -eq 0 ] ; then
      curl -s -z $DIR/$FILE -o $DIR/$FILE $URL > /dev/null 2> /dev/null
    fi
  fi
  if [ -s $DIR/$FILE ] ; then
    pushd . > /dev/null
    cd $DIR
    unzip -o $FILE compiler.jar > /dev/null 2> /dev/null
    popd > /dev/null
  fi
fi

$DIR/remove_constants.pl $1 | $DIR/opacify.pl > ._tmpRC.js

echo -n '"use strict";'
java -jar $DIR/compiler.jar --compilation_level ADVANCED_OPTIMIZATIONS \
     --js ._tmpRC.js \
     | $DIR/digitize.pl \
     | $DIR/dewindowize.pl
     

rm -f ._tmpRC.js

