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

      cve = CVEServer::Cve.find(cve.upcase)
      if cve
        json_resp cve
      else
        not_found
      end
    end

    get '/v1/cves/:cves' do |cves|
      elements = cves.split(',').uniq
      normalized_cves = elements.select {|cve| valid_cve?(cve) }.map(&:upcase)
      bad_request if normalized_cves.empty? || normalized_cves.size > 10
      entries = CVEServer::Cve.all(id: { '$in': normalized_cves } )
      not_found if entries.none?
      json_resp entries
    end

    get '/v1/cpe/:cpe_str' do |cpe_str|
      if params.has_key?('double_encoded_fields') && params['double_encoded_fields']
        cpe_str = URI.decode(URI.decode(cpe_str))
      end
      # Multiple cpes were included
      if cpe_str.include?(",")
        bad_request unless valid_cpes?(cpe_str)
      else
        bad_request unless valid_cpe?(cpe_str)
      end

      cves = CVEServer::Cve.all_cpes_equal(cpe_str.downcase)
      if cves.count.positive?
        json_resp cves
      else
        not_found
      end
    end

    get '/v1/cpe' do
      json_resp CVEServer::Cpe.all
    end

    get '/v1/cpes_affected/:cpe_str' do |cpe_str|
      cpe_str.downcase!

      if params.has_key?('double_encoded_fields') && params['double_encoded_fields']
        cpe_str = URI.decode(URI.decode(cpe_str))
      end

      bad_request unless valid_cpes?(cpe_str)

      cpes = cpe_str.split(/\s*,\s*/)
      cves = CVEServer::Cve.all_cpes_affected(cpes)
      if cves.count.positive?
        json_resp cves
      else
        not_found
      end
    end

    get '/v1/cpes_affected/?' do
      json_resp CVEServer::Cve.all_cpes_affected
    end

    get '/v1/cpe_with_version/:cpe_str' do |cpe_str|
      if params.has_key?('double_encoded_fields') && params['double_encoded_fields']
        cpe_str = URI.decode(URI.decode(cpe_str))
      end
      # Multiple cpes were included
      if cpe_str.include?(",")
        bad_request unless valid_cpes_with_version?(cpe_str)
      else
        bad_request unless valid_cpe_with_version?(cpe_str)
      end

      cves = CVEServer::Cve.all_cpes_with_version_equal(cpe_str.downcase)
      if cves.count.positive?
        json_resp cves
      else
        not_found
      end
    end

    get '/v1/cpe_with_version' do
      json_resp CVEServer::CpeWithVersion.all
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
