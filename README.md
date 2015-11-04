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

6. Start the server.

        RACK_ENV=development puma

## Using the API

* Search for an specific CVE using its ID

        http://localhost:port/v1/cve/CVE-2015-3900


* Search for CVEs related to a CPE without versions

        http://localhost:port/v1/cpe/apache:camel

        http://localhost:port/v1/cpe/apache:camel,apache:http_server

* List all the available CPEs with versions

        http://localhost:port/v1/cpe

* Search for CVEs related to a CPE with versions

        http://localhost:port/v1/cpe/apache:camel:2.11.3

        http://localhost:port/v1/cpe/apache:camel:2.11.3,apache:http_server:2.4.4

        Don't forget to encode the URI if that has special characters, example:

        URI::encode('/v1/cpe/cisco:ios:15.4%282%29t1')

* List all the available CPEs with versions

        http://localhost:port/v1/cpe_with_versions

## Additional Information

  * [Deploying the CVE Server with Capistrano and Ngnix](https://github.com/SpiderLabs/cve_server/wiki/Deploying-the-CVE-Server-with-Capistrano-and-Ngnix)

## License
  CVEServer is released under the [MIT License](http://www.opensource.org/licenses/MIT)
