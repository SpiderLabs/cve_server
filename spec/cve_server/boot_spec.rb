require 'spec_helper'
require 'cve_server/boot'

describe CVEServer::Boot do
  describe 'CVEServer::Boot included in a class' do
    before :all do
      class BootTestClass
        include CVEServer::Boot
      end
      @class = BootTestClass.new
    end

    it 'should have a CveService::Config instance in the config method' do
      expect(@class.config).to be_an_instance_of(CVEServer::Config)
    end

    it 'should have a CveService::DB::Connection instance in the connection method' do
      expect(@class.connection).to be_an_instance_of(CVEServer::DB::Connection)
    end

    it 'should not have  a nil db objectx' do
      expect(@class.db).not_to be nil
    end
  end
end
