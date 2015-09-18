# CVEServer

Simple REST-style web service for the CVE searching

# Requirements

  * Ruby 2.x.x
  * Mongo
  * Ruby bundler

# Installation

  * Clone our repository

    $ git clone https://github.com/SpiderLabs/cve_server.git

  * Install the ruby dependencies

    $ bundle install

  * Download the raw data from the National Vulnerability Database

    $ ./bin/nvd_downloader

  * Configure your database

    $ vi config/database.yml

  * Create and populate the database for you environment

    $ RACK_ENV=development ./bin/seed

  * Create and populate the database

    $ RACK_ENV=development ./bin/seed

  * Start the server

    $ RACK_ENV=development puma

# Using the API

  * Search for an specific CVE using its ID

    http://localhost:port/v1/cve/CVE-ID

  * Search for CVEs related to any cpe

    http://localhost:port/v1/cpe/php:php

  * List all the available CPEs

    http://localhost:port/v1/cpe/

    http://localhost:port/v1/cpe/microsoft:windows
