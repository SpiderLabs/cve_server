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

start_app()
{
  local __program='bundle exec puma'
  export RACK_ENV=$rack_env
  ${__program}
}

verify_required_programs
clone_git_repository
cd $dest_dir
install_ruby_bundler
install_ruby_gems
download_nvd_reports
seed_collections
start_app
