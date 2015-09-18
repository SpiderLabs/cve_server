source 'https://rubygems.org'

gem 'sinatra', '~> 1.4.6'
gem 'sinatra-json', '~> 0.1.0'
gem 'nokogiri', '~> 1.6.6.2'
gem 'mongo', '~> 2.1.0'
gem 'puma', '~> 2.13.4'

group :production do
  gem 'capistrano', '~> 3.4.0'
  gem 'capistrano-bundler', '~> 1.1.4'
  gem 'capistrano-rvm', '~> 0.1.2'
  gem 'capistrano3-puma', '~> 1.2.1'
end

group :development, :test do
  gem 'pry', '~> 0.10.1'
  gem 'rspec', '~> 3.3.0'
  gem 'rack-test', '~> 0.6.3'
  gem 'simplecov', '~> 0.10.0', :require => false
end
