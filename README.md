# CVEServer

Simple REST-style web service for the CVE searching.

## Requirements

  * [Ruby Version Manager](https://rvm.io)
  * [Ruby 2.2.3](https://www.ruby-lang.org)
  * [Bundler](http://bundler.io)
  * [Mongo DB](https://www.mongodb.org)

## Getting Started

1. Clone our repository.

        git clone https://github.com/SpiderLabs/cve_server.git

2. Install the ruby dependencies.

        bundle install

3. Download the raw data from the National Vulnerability Database

        ./bin/nvd_downloader

4. Configure your database.

        vi config/database.yml

5. Create and populate the database for you environment.

        RACK_ENV=development ./bin/seed

6. Create and populate the database.

        RACK_ENV=development ./bin/seed

7. Start the server.

        RACK_ENV=development puma

## Using the API

* Search for an specific CVE using its ID

        http://localhost:port/v1/cve/CVE-ID

* Search for CVEs related to a CPE

        http://localhost:port/v1/cpe/apache:camel:2.11.3

* List all the available CPEs

        http://localhost:port/v1/cpe/

## Additional Information

  * [Deploying the CVE Server with Capistrano and Ngnix](https://github.com/SpiderLabs/cve_server/wiki/Deploying-the-CVE-Server-with-Capistrano-and-Ngnix)
