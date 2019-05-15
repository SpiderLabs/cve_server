require 'spec_helper'
require 'cve_server/nvd/entry'
require 'zlib'
require 'nokogiri'

describe CVEServer::NVD::Entry do
  before :all do
    @infile = File.expand_path('../../../fixtures/nvd_data/partial-nvdcve-2.0-2014.xml.gz', __FILE__)
    @xml = Zlib::GzipReader.open(@infile).read
    @doc = Nokogiri::XML(@xml)
    @entry = @doc.xpath('//xmlns:entry').first
    @nvd_entry = CVEServer::NVD::Entry.new(@entry)
  end

  it 'should be an instance of CVEServer::NVD::Entry' do
    expect(@nvd_entry).to be_an_instance_of(CVEServer::NVD::Entry)
  end

  it 'should have the CVE attributes' do
    expect(@nvd_entry.to_hash.keys).to include(:id, :summary, :cwe, :published_at, :updated_at, :cvss, :references, :cpes)
  end

  it 'should have the CVE ID CVE-2014-0001' do
    expect(@nvd_entry.to_hash[:id]).to eq 'CVE-2014-0001'
  end
end
