require 'spec_helper'
require 'cve_server/db/document'

describe CVEServer::DB::Document do
  describe 'CVEServer::DB::Document included in a class' do
    before :all do
      # Dummy class
      class Cve
        include CVEServer::DB::Document
        collection_name :cves
      end
    end

    it 'should find one record' do
      expect(Cve.find(id: 'CVE-2014-0001')).to have_key('id')
    end
  end
end
