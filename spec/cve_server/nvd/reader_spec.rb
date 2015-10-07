require 'spec_helper'
require 'cve_server/nvd/reader'
require 'zlib'

describe CVEServer::NVD::Reader do
  before :all do
    @infile = File.expand_path('../../../fixtures/nvd_data/partial-nvdcve-2.0-2014.xml.gz', __FILE__)
    @xml = Zlib::GzipReader.open(@infile).read
    @nvd_reader = CVEServer::NVD::Reader.new(@xml)
  end

  it 'Should return an array with CVEs' do
    expect(@nvd_reader.all_cve).to be_a(Array)
  end

  it 'Should return 17 entries for CVEs' do
    expect(@nvd_reader.all_cve.size).to eq 19
  end

  it 'Should pass each CVE as a Hash' do
    @nvd_reader.each_cve do |cve|
      expect(cve).to be_an_instance_of(Hash)
    end
  end
end
