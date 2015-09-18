require 'rspec'
require 'rack/test'
require 'json'
require 'simplecov'

ENV['RACK_ENV'] = 'test'
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)

SimpleCov.start

module CVEServer
  module TestHelper
    def response_content_type
      last_response.headers['Content-Type']
    end

    def json_response
      JSON.parse(last_response.body)
    end
  end
end

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
  conf.include CVEServer::TestHelper
end
