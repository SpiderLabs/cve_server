#!/usr/bin/env bash

remote_repository='https://github.com/SpiderLabs/cve_server.git'
dest_dir='cve_server'
rack_env='production'

verify_program()
{
  local __program=$1
  local __binary=`which $1`
  if ! [[ -f "${__binary}" && -s "${__binary}" && -x "${__binary}" ]]
  then
     echo "You must install ${__program}"
     exit 1
  fi
}

ruby_version()
{
  local __version=`ruby --version | cut -f2 -d" "`
  echo $__version
}

verify_ruby_version()
{
  local __ruby_version=`echo $(ruby_version) | sed -E 's/\.[0-9]+p[0-9]+$//'`
  local __min_required_version=2.0
  if ! (( $(echo "${__ruby_version} >= ${__min_required_version}" |bc -l) ))
  then
    echo "You must install ruby 2.x.x or later version"
    exit 1
  fi
}

verify_required_programs()
{
  for program in git mongod ruby
  do
    verify_program $program
  done
  verify_ruby_version
}

install_ruby_bundler()
{
  if ! (gem list | grep -i bundler)
  then
    gem install bundler
  fi
}

install_ruby_gems()
{
  bundler install
}

clone_git_repository()
{
  if [ -d "$dest_dir" ]
  then
    echo "You must delete the local directory $dest_dir"
    exit 1
  else
    git clone $remote_repository $dest_dir
  fi
}

download_nvd_reports()
{
  local __program='./bin/nvd_downloader'
  ${__program}
}


seed_collections()
{
  local __program='./bin/seed'
  export RACK_ENV=$rack_env
  ${__program}
}

start_puma()
{
  local __program='bundle exec puma'
  export RACK_ENV=$rack_env
  ${__program}
}

puma_instructions()
{
  echo $(printf "%0.s=" {1..74})
  echo "Test your local server at http://0.0.0.0:9292/v1/cve/CVE-2015-6939"
  echo -e "Check the README.md file to look for the available API actions.\n"
}

crontab_instructions()
{
  echo $(printf "%0.s=" {1..74})
  echo -e "The daily update from NVD could be executed from your crontab:\n"
  APP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
  update_db_path="$(pwd)/scripts/update_db.sh"
  echo -e "00 2 * * * $update_db_path\n"
}

ngnix_conf()
{
  echo $(printf "%0.s=" {1..74})
  echo -e "You could add the following configuration into you ngnix server:\n"
cat << EOF

upstream cve_server {
  server unix://$(pwd)/shared/tmp/sockets/puma.sock;
}

server {
  listen 80 default_server;
  root $(pwd)/public;

  server_name localhost;
  location / {
    proxy_pass http://cve_server;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
  }
}

EOF
}

install() {
  verify_required_programs
  clone_git_repository
  cd $dest_dir
  install_ruby_bundler
  install_ruby_gems
  download_nvd_reports
  seed_collections
  start_puma
  if ps awx| grep puma > /dev/null;
  then
    puma_instructions
    ngnix_conf
    crontab_instructions
  fi
}

install
