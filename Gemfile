source 'https://rubygems.org'

gem 'sinatra', '~> 2.0.3'
gem 'sinatra-contrib', '~> 2.0.3'
gem 'nokogiri', '~> 1.8.2'
gem 'mongo', '~> 2.1.2'
gem 'puma', '~> 3.11.4'

group :production do
  gem 'capistrano', '~> 3.9.0'
  gem 'capistrano-bundler', '~> 1.2.0'
  gem 'capistrano-rvm', '~> 0.1.2'
  gem 'capistrano3-puma', '~> 3.1.1'
end

group :development, :test do
  gem 'pry', '~> 0.11.3'
  gem 'rspec', '~> 3.7.0'
  gem 'rack-test', '~> 1.1.0'
  gem 'simplecov', '~> 0.16.1', :require => false
end
