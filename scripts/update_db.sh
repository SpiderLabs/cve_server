#!/usr/bin/env bash

APP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
if [ -d "$APP_DIR" ]
then
  killall -9 puma
  $APP_DIR/bin/seed RACK_ENV=production;
  export RACK_ENV=production
  cd $APP_DIR && puma ;
else
   echo "The $APP_DIR doesn't exist"
   exit 1
fi
