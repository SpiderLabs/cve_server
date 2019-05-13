require 'spec_helper'
require 'zlib'
require 'cve_server/nvd/json/entry'

describe CVEServer::NVD::JSON::Entry do
  context 'when it receives a valid entry from the NVD dataset' do
    let(:infile) {
      json_file = '../../../../fixtures/nvd_data/partial-nvdcve-1.0.json.gz'
      File.expand_path(json_file, __FILE__)
    }
    let(:input) { Zlib::GzipReader.open(infile).read }
    let(:json) { JSON.parse(input) }
    let(:entry) { json['CVE_Items'].last }
    subject { described_class.new(entry) }

    describe '#id' do
      it 'should return the CVE-2017-0016' do
        expect(subject.id).not_to be_nil
        expect(subject.id).to eq('CVE-2017-0016')
      end
    end

    describe '#summary' do
      it 'should return the expected summary' do
        s = "Microsoft Windows 10 Gold, 1511, and 1607; Windows 8.1; Windows " \
            "RT 8.1; Windows Server 2012 R2, and Windows Server 2016 do not " \
            "properly handle certain requests in SMBv2 and SMBv3 packets, " \
            "which allows remote attackers to execute arbitrary code via a "  \
            "crafted SMBv2 or SMBv3 packet to the Server service, aka "  \
            "\"SMBv2/SMBv3 Null Dereference Denial of Service Vulnerability.\""
        expect(subject.summary).not_to be_nil
        expect(subject.summary).to eq(s)
      end
    end

    describe '#cwe' do
      it 'should return the CWE-476' do
        expect(subject.cwe).not_to be_nil
        expect(subject.cwe).to eq('CWE-476')
      end
    end

    describe '#published_at' do
      it 'should return the published_at date' do
        date = Time.parse('2017-03-17 00:59:00.000000000 +0000')
        expect(subject.published_at).not_to be_nil
        expect(subject.published_at).to eq(date)
      end
    end

    describe '#updated_at' do
      it 'should return the updated_at date' do
        date = Time.parse('2017-07-25 01:29:00.000000000 +0000')
        expect(subject.updated_at).not_to be_nil
        expect(subject.updated_at).to eq(date)
      end
    end

    describe '#cvssv2' do
      it 'should return the cvss version 2' do
        expected_cvssv2 = {
          :version => "2.0",
          :access_complexity => "MEDIUM",
          :access_vector => "NETWORK",
          :authentication => "NONE",
          :availability_impact => "COMPLETE",
          :base_score => 7.1,
          :confidentiality_impact => "NONE",
          :integrity_impact => "NONE",
          :vector => "AV:N/AC:M/Au:N/C:N/I:N/A:C",
        }
        expect(subject.cvssv2).not_to be_nil
        expect(subject.cvssv2).to eq(expected_cvssv2)
      end
    end

    describe '#cvssv3' do
      it 'should return the cvss version 3' do
        expected_cvssv3 = {
          :version => "3.0",
          :attack_complexity => "HIGH",
          :attack_vector => "NETWORK",
          :availability_impact => "HIGH",
          :base_score => 5.9,
          :base_severity => "MEDIUM",
          :confidentiality_impact => "NONE",
          :integrity_impact => "NONE",
          :privileges_required => "NONE",
          :scope => "UNCHANGED",
          :user_interaction => "NONE",
          :vector => "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        }
        expect(subject.cvssv3).not_to be_nil
        expect(subject.cvssv3).to eq(expected_cvssv3)
      end
    end

    describe '#references' do
      it 'should return the references' do
        expected_references =  [
          { :href=>"http://www.securityfocus.com/bid/95969" },
          { :href=>"http://www.securitytracker.com/id/1037767" },
          { :href=>"http://www.securitytracker.com/id/1038001" },
          { :href=> "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0016" }
        ]
        expect(subject.references).not_to be_nil
        expect(subject.references).to eq(expected_references)
      end
    end

    describe '#cpes' do
      it 'should return the cpes' do
        expected_cpes =  [
          "microsoft:windows_10",
          "microsoft:windows_8.1",
          "microsoft:windows_rt_8.1",
          "microsoft:windows_server_2012",
          "microsoft:windows_server_2016"
        ]
        cpes = subject.cpes
        expect(subject.cpes).not_to be_nil
        expect(subject.cpes).to eq(expected_cpes)
      end
    end

    describe '#cpes_with_version' do
      it 'should return the cpes with version' do
        expected_cpes =  [
          "microsoft:windows_10:-",
          "microsoft:windows_10:1511",
          "microsoft:windows_10:1607",
          "microsoft:windows_8.1",
          "microsoft:windows_rt_8.1",
          "microsoft:windows_server_2012:r2",
          "microsoft:windows_server_2016"
        ]
        cpes = subject.cpes
        expect(subject.cpes_with_version).not_to be_nil
        expect(subject.cpes_with_version).to eq(expected_cpes)
      end
    end

    describe '#to_hash' do
      it 'should return an instance of Hash class' do
        expect(subject.to_hash).to be_instance_of(Hash)
      end
      it 'should return a non-empty hash' do
        expect(subject.to_hash).not_to be_empty
      end
    end

    describe 'Private methods' do
      describe '#attribute' do
        context 'when the key exists' do
          it 'should return the value' do
            expect(subject.send(:attribute,'cve', 'description')).not_to be_empty
          end
        end
        context 'when the key does not exist' do
          it 'should return the nil value' do
            expect(subject.send(:attribute,'cve', 'invalid_key')).to be_nil
          end
        end
      end

      describe '#time_at' do
        context 'when there is a valid time string' do
          it 'should parse the string and return a Time object' do
            expect(subject.send(:time_at, 'publishedDate')).to be_instance_of(Time)
          end
        end
        context 'when there is an invalid value' do
          it 'should raise an TypeError exception' do
            expect{ subject.send(:time_at,'cve') }.to raise_error(TypeError)
          end
        end
        context 'when there is an invalid key' do
          it 'should return nil' do
            expect(subject.send(:time_at,'invalid_key')).to be_nil
          end
        end
      end

      describe '#normalize_key' do
        context 'when there is a key with upcase characters' do
          it 'should return a key with snake case format' do
            expect(subject.send(:normalize_key, 'cvssScore')).to eq('cvss_score')
          end
        end
        context 'when there is a key without upcase characters' do
          it 'should return the key with the original string' do
            expect(subject.send(:normalize_key, 'cvss')).to eq('cvss')
          end
        end
      end

      describe '#full_cpes' do
        context 'when the configurations hash has values for the nodes key ' do
          it 'shoudl return an array of 7 strings' do
            expect(subject.send(:full_cpes)).not_to be_empty
            expect(subject.send(:full_cpes).size).to eq(7)
          end
        end
        context 'when the configurations hash does not have the nodes key' do
          it 'should return an empty array' do
            allow(subject).to receive(:attribute).with('configurations', 'nodes')
              .and_return(nil)
            expect(subject.send(:full_cpes)).to be_empty
          end
        end
      end
    end
  end

  context 'when a CPE configuration node has children' do
    let(:infile) {
      json_file = '../../../../fixtures/nvd_data/partial-nvdcve-1.0-CVE-2019-1694.json.gz'
      File.expand_path(json_file, __FILE__)
    }
    let(:input) { Zlib::GzipReader.open(infile).read }
    let(:json) { JSON.parse(input) }
    let(:entry) { json['CVE_Items'].last }
    subject { described_class.new(entry) }

    describe '#cpes' do
      it 'should return all CPEs' do
        expected_cpes = [
          "cisco:adaptive_security_appliance_software",
          "cisco:asa_5505",
          "cisco:asa_5510",
          "cisco:asa_5512-x",
          "cisco:asa_5515-x",
          "cisco:asa_5520",
          "cisco:asa_5525-x",
          "cisco:asa_5540",
          "cisco:asa_5545-x",
          "cisco:asa_5550",
          "cisco:asa_5555-x",
          "cisco:asa_5580",
          "cisco:asa_5585-x",
          "cisco:firepower_threat_defense"
        ]
        expect(subject.cpes).not_to be_nil
        expect(subject.cpes).to eq(expected_cpes)
      end
    end

    describe '#cpes_with_version' do
      it 'should return all CPEs with versions' do
        expected_cpes = [
          "cisco:adaptive_security_appliance_software",
          "cisco:asa_5505:-",
          "cisco:asa_5510:-",
          "cisco:asa_5512-x:-",
          "cisco:asa_5515-x:-",
          "cisco:asa_5520:-",
          "cisco:asa_5525-x:-",
          "cisco:asa_5540:-",
          "cisco:asa_5545-x:-",
          "cisco:asa_5550:-",
          "cisco:asa_5555-x:-",
          "cisco:asa_5580:-",
          "cisco:asa_5585-x:-",
          "cisco:firepower_threat_defense"
        ]
        expect(subject.cpes_with_version).not_to be_nil
        expect(subject.cpes_with_version).to eq(expected_cpes)
      end
    end
  end
end
