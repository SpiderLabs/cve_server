require 'spec_helper'
require 'zlib'
require 'cve_server/nvd/json/reader'

describe CVEServer::NVD::JSON::Reader do
  context 'when it receives a valid JSON input from NVD' do
    let(:infile) {
      json_file = '../../../../fixtures/nvd_data/partial-nvdcve-1.0.json.gz'
      File.expand_path(json_file, __FILE__)
    }
    let(:input) { Zlib::GzipReader.open(infile).read }
    subject { described_class.new(input) }
    
    describe '#all_entries' do
      it 'should return an array with 15 elements' do
        expect(subject.all_entries).to be_a(Array)
        expect(subject.all_entries.size).to eq 15
      end
    end
    
    describe '#all_cve' do
      it 'should return an array with CVEs' do
        expect(subject.all_cve).to be_a(Array)
      end
      
      it 'should return 15 entries for CVEs' do
        expect(subject.all_cve.size).to eq 15
      end
    end
    
    describe '#each_cve' do
      it 'should pass each CVE as a Hash' do
        subject.each_cve do |cve|
          expect(cve).to be_an_instance_of(Hash)
        end
      end
    end
  end
  
  context 'when it receives an invalid JSON input' do
    subject { described_class.new({invalid_content:[]}.to_json) }
    
    describe '#all_entries' do
      it 'should return an empty array' do
        expect(subject.all_entries).to be_empty
      end
    end
    
    describe '#all_cve' do
      it 'should return 0 entries for CVEs' do
        expect(subject.all_cve.size).to eq 0
      end
    end
  end
end
