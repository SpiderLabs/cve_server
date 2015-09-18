require 'spec_helper'
require 'cve_server/config'

describe CVEServer::Config  do
  before :all do
    @conf = CVEServer::Config.new
  end

  it 'should be a test environment' do
    expect(@conf.env).to eq 'test'
  end

  it 'should have the mongo database adapter' do
    expect(@conf.db_adapter).to eq 'mongo'
  end

  it 'should have mongo connection options' do
    expect(@conf.db_options).to include({'database' => 'cves_test' })
  end

  it 'should not have a raw data path empty' do
    expect(@conf.raw_data_path).not_to be_empty
  end
end
