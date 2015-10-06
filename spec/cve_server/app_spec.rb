require 'spec_helper'
require 'cve_server/app'

describe CVEServer::App do
  def app
    @app ||= CVEServer::App
  end

  describe 'Specs for /v1/cve/:cve' do
    describe 'GET /v1/cve/CVE-2014-0001' do
      it 'should be successful' do
        get '/v1/cve/CVE-2014-0001'
        expect(last_response).to be_ok
      end

      it 'should be case insensitive' do
        get '/v1/cve/cve-2014-0001'
        expect(last_response).to be_ok
      end

      it 'should return content-type as json' do
        get '/v1/cve/CVE-2014-0001'
        expect(response_content_type).to eq 'application/json'
      end

      it 'shoud not be emtpy' do
        get '/v1/cve/CVE-2014-0001'
        expect(last_response).not_to be_empty
      end

      it 'should return json with the CVE-2014-0001 ID' do
        get '/v1/cve/CVE-2014-0001'
        expect(json_response['id']).to eq 'CVE-2014-0001'
      end

      it 'should return json with the CVE-2014-0001 ID' do
        get '/v1/cve/cVe-2014-0001'
        expect(json_response['id']).to eq 'CVE-2014-0001'
      end

      it 'should expect status equal to 200' do
        get '/v1/cve/CVE-2014-0001'
        expect(last_response.status).to eq(200)
      end

      it 'should expect status equal to 200 using downcase characters' do
        get '/v1/cve/cve-2014-0001'
        expect(last_response.status).to eq(200)
      end
    end

    describe 'GET /v1/cve/CVE-1000-0001' do
      it 'should return not found error message' do
        get '/v1/cve/CVE-1000-0001'
        expect(json_response['error']).to eq 'not-found'
      end

      it 'should return status equel to 404' do
        get '/v1/cve/CVE-1000-0001'
        expect(last_response.status).to eq(404)
      end
    end

    describe 'GET /v1/cve/bad-requests' do
      it 'should return invalid parameters message' do
        get '/v1/cve/bad-request'
        expect(json_response['error']).to eq 'invalid-parameters'
      end

      it 'should return status equal to 400' do
        get '/v1/cve/bad-request'
        expect(last_response.status).to eq(400)
      end
    end
  end

  describe 'Specs for /v1/cpe/:cpe' do
    describe 'GET /v1/cpe/apache:camel:2.11.3' do
      it 'should be successful' do
        get '/v1/cpe/apache:camel:2.11.3'
        expect(last_response).to be_ok
      end

      it 'should be case insensitive' do
        get '/v1/cpe/apache:CAMEL:2.11.3'
        expect(last_response).to be_ok
      end

      it 'should return content-type as json' do
        get '/v1/cpe/apache:camel:2.11.3'
        expect(response_content_type).to eq 'application/json'
      end

      it 'shoud not be emtpy' do
        get '/v1/cpe/apache:camel:2.11.3'
        expect(last_response).not_to be_empty
      end

      it 'should return json with a CVE array' do
        get '/v1/cpe/apache:camel:2.11.3'
        expect(json_response).to eq ['CVE-2014-0002', 'CVE-2014-0003']
      end

      it 'should expect status equal to 200' do
        get '/v1/cpe/apache:camel:2.11.3'
        expect(last_response.status).to eq(200)
      end

      it 'should expect status equal to 200 using upcase characters' do
        get '/v1/cpe/apache:CAMEL:2.11.3'
        expect(last_response.status).to eq(200)
      end
    end

    describe 'GET /v1/cpe/oracle:mysql' do
      it 'should return not found error message' do
        get '/v1/cpe/oracle:mysql'
        expect(json_response['error']).to eq 'not-found'
      end

      it 'should return status equal to 404' do
        get '/v1/cpe/oracle:mysql'
        expect(last_response.status).to eq(404)
      end
    end

    describe 'GET /v1/cpe/bad$requests+' do
      it 'should return invalid parameters message' do
        get '/v1/cpe/bad$request+'
        expect(json_response['error']).to eq 'invalid-parameters'
      end

      it 'should return status equel to 400' do
        get '/v1/cpe/bad$request+'
        expect(last_response.status).to eq(400)
      end
    end
  end

  describe 'Specs for /v1/cve' do
    describe 'GET /v1/cve' do
      it 'should be successful' do
        get '/v1/cpe'
        expect(last_response).to be_ok
      end

      it 'should return content-type as json' do
        get '/v1/cpe'
        expect(response_content_type).to eq 'application/json'
      end

      it 'should return json with an array including the CPE mysql:mysql, pocoo:jinja2, mariadb:mariadb' do
        get '/v1/cpe'
        expect(json_response).to include('mysql:mysql', 'pocoo:jinja2:2.7.2', 'mariadb:mariadb:5.5.34')
      end

      it 'should return json with an array with 18 CPE strings' do
        get '/v1/cpe'
        expect(json_response.size).to eq 470
      end

      it 'should expect status equal to 200' do
        get '/v1/cpe'
        expect(last_response.status).to eq(200)
      end
    end
  end
end
