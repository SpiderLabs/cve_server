require 'sinatra'
require 'sinatra/json'
require 'cve_server'

module CVEServer
  # CVEServer::App is the CVE Micro Service API
  class App < Sinatra::Base
    include CVEServer::Helper

    before do
      content_type 'application/json'
    end

    get '/v1/cve/:cve' do |cve|
      bad_request unless valid_cve?(cve)

      @cve = CVEServer::Cve.find(cve.upcase)
      if @cve
        json_resp @cve
      else
        not_found
      end
    end

    get '/v1/cpe/:cpes' do |cpes|
      # Multiple cpes were included
      if cpes.include?(",")
        bad_request unless valid_cpes?(cpes)
        @cves = CVEServer::Cve.all_cpes_equal(cpes.downcase)
      else
        bad_request unless valid_cpe?(cpes)
        @cves = CVEServer::Cve.all_cpe_equal(cpes.downcase)
      end

      if @cves.count > 0
        json_resp @cves
      else
        not_found
      end
    end

    get '/v1/cpe' do
      json_resp CVEServer::Cpe.all
    end

    private

    def json_resp(body)
      json body, status: 200
    end

    def not_found
      halt 404, json(error: 'not-found')
    end

    def bad_request
      halt 400, json(error: 'invalid-parameters')
    end
  end
end
