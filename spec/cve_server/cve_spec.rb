require 'spec_helper'
require 'cve_server/cve'

describe CVEServer::Cve do
  describe '#all_cpes_affected' do
    context 'when no CPEs are provided' do
      it 'should return the expected affected CPEs' do
        expected_results = [
          "apache:camel",
          "cisco:adaptive_security_appliance_software",
          "cisco:firepower_threat_defense",
          "mariadb:mariadb",
          "microsoft:edge",
          "microsoft:excel",
          "microsoft:excel_viewer",
          "microsoft:internet_explorer",
          "microsoft:office",
          "microsoft:office_compatibility_pack",
          "microsoft:sharepoint_enterprise_server",
          "microsoft:sharepoint_server",
          "microsoft:windows_10",
          "microsoft:windows_7",
          "microsoft:windows_8.1",
          "microsoft:windows_rt_8.1",
          "microsoft:windows_server_2008",
          "microsoft:windows_server_2012",
          "microsoft:windows_server_2016",
          "microsoft:windows_vista",
          "microsoft:word",
          "mysql:mysql",
          "oracle:mysql",
          "redhat:enterprise_linux",
          "redhat:enterprise_linux_desktop",
          "redhat:enterprise_linux_server",
          "redhat:enterprise_linux_workstation"
        ]
        expect(described_class.all_cpes_affected).to match_array(expected_results)
      end
    end

    context 'when provided an array of CPEs' do
      it 'should return the expected CVEs' do
        expected_results = ["CVE-2014-0002", "CVE-2014-0003", "CVE-2017-0002", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012", "CVE-2017-0015"]
        result = described_class.all_cpes_affected(%w{apache:camel microsoft:edge})
        expect(result).to match_array(expected_results)
      end
    end

    context 'when provided a String of valid CPEs' do
      it 'should return the expected CVEs' do
        expected_results = ["CVE-2017-0002", "CVE-2017-0010", "CVE-2017-0011", "CVE-2017-0012", "CVE-2017-0015"]
        result = described_class.all_cpes_affected('microsoft:edge')
        expect(result).to match_array(expected_results)
      end
    end

    context 'when provided anything but an Array or String' do
      it 'should return the expected CVEs' do
        expect { described_class.all_cpes_affected(12345) }.to raise_error(TypeError)
      end
    end
  end
end
