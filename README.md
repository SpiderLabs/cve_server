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

## Deploying the CVE Server with Capistrano and Ngnix

1. Create a user for the deployment in your production machine.

        sudo adduser -c 'CVE Server deployer' deployer

2. Install RVM, Ruby, MongoDB and Gninx in your production machine.

        gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3

        curl -sSL https://get.rvm.io | bash -s stable

        rvm install ruby-2.2.3

        apt-get install nginx mongodb

3. Edit the capistrano files under the config directory in your local repository.

        vi config/deploy.rb

        vi config/deploy/production.rb

4. Run the deployment commands.

        cap RACK_ENV=production deploy
        cap RACK_ENV=production deploy:download_nvd_reports
        cap RACK_ENV=production deploy:seed

5. Configure the ngnix server in your production machine.

        upstream cve_server {
          server unix://home/deployer/cve_server/shared/tmp/sockets/puma.sock;
        }
        server {
          listen 80 default_server;
          root /home/deployer/cve_server/current/public;

          server_name localhost;
            location / {
              proxy_pass http://cve_server;
              proxy_set_header Host $host;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_buffering off;
            }
        }

6. Add puma as a daemon service in your production machine.

        https://github.com/puma/puma/tree/master/tools/jungle/init.d

7. Save this script to update your database from the cron using your deployment user.

        vi /home/deployer/bin/cve_server_update.sh

        #!/bin/bash
        [ -s "$HOME/.rvm/scripts/rvm" ] && source "$HOME/.rvm/scripts/rvm"
        app="/home/deployer/cve_server/current"
        cd $app; bundle exec ./bin/nvd_downloader; bundle exec ./bin/seed RACK_ENV=production

        chmod u+x /home/deployer/bin/cve_server_update.sh

8. Add the following line into the crontab of the deployment user to execute this every day at 2:00 am.

        0 2 * * * /home/deployer/bin/cve_server_update.sh
