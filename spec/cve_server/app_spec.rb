require 'spec_helper'
require 'cve_server/app'

shared_examples "good response results" do |url, expected_results|
  describe "verifying the response for #{url}" do
    before :all do
      get url
    end

    it 'response should be ok' do
      expect(last_response).to be_ok
    end

    it 'response is not empty' do
      expect(last_response).not_to be_empty
    end

    it 'response status code is 200' do
      expect(last_response.status).to eq(200)
    end

    it 'response content type is json' do
      expect(response_content_type).to eq 'application/json'
    end

    it 'json response should match expected results' do
      expect(json_response).to eq expected_results
    end

  end
end

shared_examples "a good parameter handler" do |url, good_parameters, unknown_good_parameters, invalid_parameters|
  describe "handling good known parameters" do
    good_parameters.each do |parameter, expected_results|
      it_behaves_like "good response results", "#{url}#{parameter}", expected_results
    end
  end

  describe "handling unknown good parameters" do
    unknown_good_parameters.each do |parameter|
      it "should error on #{parameter}" do
        get "#{url}#{parameter}"
        expect(last_response.status).to eq(404)
        expect(json_response['error']).to eq 'not-found'
      end
    end
  end

  describe "handling invalid parameters" do
    invalid_parameters.each do |parameter|
      it "should error on #{parameter}" do
        get "#{url}#{parameter}"
        expect(last_response.status).to eq(400)
        expect(json_response['error']).to eq 'invalid-parameters'
      end
    end
  end
end

describe CVEServer::App do
  def app
    @app ||= CVEServer::App
  end

  describe '/v1/cve/:cve' do
    url = "/v1/cve/"
    good_cves = {
      "CVE-2014-0001" => {
        "id" => "CVE-2014-0001",
        "summary" => "Buffer overflow in client/mysql.cc in Oracle MySQL and MariaDB before 5.5.35 allows remote database servers to cause a denial of service (crash) and possibly execute arbitrary code via a long server version string.",
        "cwe" => "CWE-119",
        "published_at" => "2014-01-31 23:55:00 UTC",
        "updated_at" => "2019-04-22 17:48:00 UTC",
        "cvss" => {
          "access_vector" => "NETWORK",
          "access_complexity" => "LOW",
          "authentication" => "NONE",
          "confidentiality_impact" => "PARTIAL",
          "integrity_impact" => "PARTIAL",
          "availability_impact" => "PARTIAL",
          "base_score" => 7.5,
          "vector" => "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        },
        "cvssv3" => nil,
        "references" => [
          {"href" => "http://bazaar.launchpad.net/~maria-captains/maria/5.5/revision/2502.565.64"},
          {"href" => "http://osvdb.org/102713"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0164.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0173.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0186.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0189.html"},
          {"href" => "http://secunia.com/advisories/52161"},
          {"href" => "http://security.gentoo.org/glsa/glsa-201409-04.xml"},
          {"href" => "http://www.mandriva.com/security/advisories?name=MDVSA-2014:029"},
          {"href" => "http://www.osvdb.org/102714"},
          {"href" => "http://www.securityfocus.com/bid/65298"},
          {"href" => "http://www.securitytracker.com/id/1029708"},
          {"href" => "https://bugzilla.redhat.com/show_bug.cgi?id=1054592"},
          {"href" => "https://exchange.xforce.ibmcloud.com/vulnerabilities/90901"},
          {"href" => "https://mariadb.com/kb/en/mariadb-5535-changelog/"}
        ],
        "cpes_affected" => [
          "mariadb:mariadb",
          "mysql:mysql",
          "oracle:mysql",
          "redhat:enterprise_linux",
          "redhat:enterprise_linux_desktop",
          "redhat:enterprise_linux_server",
          "redhat:enterprise_linux_workstation"
        ],
        "cpes" => [
          "mariadb:mariadb",
          "redhat:enterprise_linux",
          "redhat:enterprise_linux_desktop",
          "redhat:enterprise_linux_server",
          "redhat:enterprise_linux_workstation",
          "mysql:mysql",
          "oracle:mysql"
        ],
        "cpes_with_version" => [
          "mariadb:mariadb",
          "redhat:enterprise_linux:5",
          "redhat:enterprise_linux:6.0",
          "redhat:enterprise_linux_desktop:5.0",
          "redhat:enterprise_linux_desktop:6.0",
          "redhat:enterprise_linux_server:6.0",
          "redhat:enterprise_linux_workstation:6.0",
          "mysql:mysql:5.5.0",
          "mysql:mysql:5.5.1",
          "mysql:mysql:5.5.2",
          "mysql:mysql:5.5.3",
          "mysql:mysql:5.5.4",
          "mysql:mysql:5.5.5",
          "mysql:mysql:5.5.6",
          "mysql:mysql:5.5.7",
          "mysql:mysql:5.5.8",
          "mysql:mysql:5.5.9",
          "oracle:mysql:5.5.10",
          "oracle:mysql:5.5.11",
          "oracle:mysql:5.5.12",
          "oracle:mysql:5.5.13",
          "oracle:mysql:5.5.14",
          "oracle:mysql:5.5.15",
          "oracle:mysql:5.5.16",
          "oracle:mysql:5.5.17",
          "oracle:mysql:5.5.18",
          "oracle:mysql:5.5.19",
          "oracle:mysql:5.5.20",
          "oracle:mysql:5.5.21",
          "oracle:mysql:5.5.22",
          "oracle:mysql:5.5.23",
          "oracle:mysql:5.5.24",
          "oracle:mysql:5.5.25",
          "oracle:mysql:5.5.26",
          "oracle:mysql:5.5.27",
          "oracle:mysql:5.5.28",
          "oracle:mysql:5.5.29",
          "oracle:mysql:5.5.30",
          "oracle:mysql:5.5.31",
          "oracle:mysql:5.5.32",
          "oracle:mysql:5.5.33",
          "oracle:mysql:5.5.34",
          "oracle:mysql:5.5.35",
          "oracle:mysql:5.5.36",
          "oracle:mysql:5.6.0",
          "oracle:mysql:5.6.1",
          "oracle:mysql:5.6.2",
          "oracle:mysql:5.6.3",
          "oracle:mysql:5.6.4",
          "oracle:mysql:5.6.5",
          "oracle:mysql:5.6.6",
          "oracle:mysql:5.6.7",
          "oracle:mysql:5.6.8",
          "oracle:mysql:5.6.9",
          "oracle:mysql:5.6.10",
          "oracle:mysql:5.6.11",
          "oracle:mysql:5.6.12",
          "oracle:mysql:5.6.13",
          "oracle:mysql:5.6.14",
          "oracle:mysql:5.6.15",
          "oracle:mysql:5.6.16"
        ]
      },
      "CVE-2019-1694" => {
        "id" => "CVE-2019-1694",
        "summary" => "A vulnerability in the TCP processing engine of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS) condition. The vulnerability is due to the improper handling of TCP traffic. An attacker could exploit this vulnerability by sending a specific sequence of packets at a high rate through an affected device. A successful exploit could allow the attacker to temporarily disrupt traffic through the device while it reboots.",
        "cwe" => "CWE-399",
        "published_at" => "2019-05-03 15:29:00 UTC",
        "updated_at" => "2019-05-07 16:50:00 UTC",
        "cvss" => {
          "access_vector" => "NETWORK",
          "access_complexity" => "LOW",
          "authentication" => "NONE",
          "confidentiality_impact" => "NONE",
          "integrity_impact" => "NONE",
          "availability_impact" => "COMPLETE",
          "base_score" => 7.8,
          "vector" => "AV:N/AC:L/Au:N/C:N/I:N/A:C"
        },
        "cvssv3" => {
          "attack_vector" => "NETWORK",
          "attack_complexity" => "LOW",
          "privileges_required" => "NONE",
          "user_interaction" => "NONE",
          "scope" => "CHANGED",
          "confidentiality_impact" => "NONE",
          "integrity_impact" => "NONE",
          "availability_impact" => "HIGH",
          "base_score" => 8.6,
          "base_severity" => "HIGH",
          "vector" => "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"
        },
        "references" => [
          {"href" => "http://www.securityfocus.com/bid/108160"},
          {"href" => "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-frpwrtd-dos"}
        ],
        "cpes_affected" => [
          "cisco:adaptive_security_appliance_software",
          "cisco:firepower_threat_defense"
        ],
        "cpes" => [
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
        ],
        "cpes_with_version" => [
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
      }
    }

    unknown_good_cves = [
      "CVE-2015-0599",
    ]

    invalid_cves = [
      "badrequests",
    ]

    it_behaves_like "a good parameter handler", url, good_cves, unknown_good_cves, invalid_cves
  end

  describe '/v1/cves/:cves' do
    url = "/v1/cves/"
    good_cves = {
      "CVE-2014-0001" => [{
        "id" => "CVE-2014-0001",
        "summary" => "Buffer overflow in client/mysql.cc in Oracle MySQL and MariaDB before 5.5.35 allows remote database servers to cause a denial of service (crash) and possibly execute arbitrary code via a long server version string.",
        "cwe" => "CWE-119",
        "published_at" => "2014-01-31 23:55:00 UTC",
        "updated_at" => "2019-04-22 17:48:00 UTC",
        "cvss" => {
          "access_vector" => "NETWORK",
          "access_complexity" => "LOW",
          "authentication" => "NONE",
          "confidentiality_impact" => "PARTIAL",
          "integrity_impact" => "PARTIAL",
          "availability_impact" => "PARTIAL",
          "base_score" => 7.5,
          "vector" => "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        },
        "cvssv3" => nil,
        "references" => [
          {"href" => "http://bazaar.launchpad.net/~maria-captains/maria/5.5/revision/2502.565.64"},
          {"href" => "http://osvdb.org/102713"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0164.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0173.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0186.html"},
          {"href" => "http://rhn.redhat.com/errata/RHSA-2014-0189.html"},
          {"href" => "http://secunia.com/advisories/52161"},
          {"href" => "http://security.gentoo.org/glsa/glsa-201409-04.xml"},
          {"href" => "http://www.mandriva.com/security/advisories?name=MDVSA-2014:029"},
          {"href" => "http://www.osvdb.org/102714"},
          {"href" => "http://www.securityfocus.com/bid/65298"},
          {"href" => "http://www.securitytracker.com/id/1029708"},
          {"href" => "https://bugzilla.redhat.com/show_bug.cgi?id=1054592"},
          {"href" => "https://exchange.xforce.ibmcloud.com/vulnerabilities/90901"},
          {"href" => "https://mariadb.com/kb/en/mariadb-5535-changelog/"}
        ],
        "cpes_affected" => [
          "mariadb:mariadb",
          "mysql:mysql",
          "oracle:mysql",
          "redhat:enterprise_linux",
          "redhat:enterprise_linux_desktop",
          "redhat:enterprise_linux_server",
          "redhat:enterprise_linux_workstation"
        ],
        "cpes" => [
          "mariadb:mariadb",
          "redhat:enterprise_linux",
          "redhat:enterprise_linux_desktop",
          "redhat:enterprise_linux_server",
          "redhat:enterprise_linux_workstation",
          "mysql:mysql",
          "oracle:mysql"
        ],
        "cpes_with_version" => [
          "mariadb:mariadb",
          "redhat:enterprise_linux:5",
          "redhat:enterprise_linux:6.0",
          "redhat:enterprise_linux_desktop:5.0",
          "redhat:enterprise_linux_desktop:6.0",
          "redhat:enterprise_linux_server:6.0",
          "redhat:enterprise_linux_workstation:6.0",
          "mysql:mysql:5.5.0",
          "mysql:mysql:5.5.1",
          "mysql:mysql:5.5.2",
          "mysql:mysql:5.5.3",
          "mysql:mysql:5.5.4",
          "mysql:mysql:5.5.5",
          "mysql:mysql:5.5.6",
          "mysql:mysql:5.5.7",
          "mysql:mysql:5.5.8",
          "mysql:mysql:5.5.9",
          "oracle:mysql:5.5.10",
          "oracle:mysql:5.5.11",
          "oracle:mysql:5.5.12",
          "oracle:mysql:5.5.13",
          "oracle:mysql:5.5.14",
          "oracle:mysql:5.5.15",
          "oracle:mysql:5.5.16",
          "oracle:mysql:5.5.17",
          "oracle:mysql:5.5.18",
          "oracle:mysql:5.5.19",
          "oracle:mysql:5.5.20",
          "oracle:mysql:5.5.21",
          "oracle:mysql:5.5.22",
          "oracle:mysql:5.5.23",
          "oracle:mysql:5.5.24",
          "oracle:mysql:5.5.25",
          "oracle:mysql:5.5.26",
          "oracle:mysql:5.5.27",
          "oracle:mysql:5.5.28",
          "oracle:mysql:5.5.29",
          "oracle:mysql:5.5.30",
          "oracle:mysql:5.5.31",
          "oracle:mysql:5.5.32",
          "oracle:mysql:5.5.33",
          "oracle:mysql:5.5.34",
          "oracle:mysql:5.5.35",
          "oracle:mysql:5.5.36",
          "oracle:mysql:5.6.0",
          "oracle:mysql:5.6.1",
          "oracle:mysql:5.6.2",
          "oracle:mysql:5.6.3",
          "oracle:mysql:5.6.4",
          "oracle:mysql:5.6.5",
          "oracle:mysql:5.6.6",
          "oracle:mysql:5.6.7",
          "oracle:mysql:5.6.8",
          "oracle:mysql:5.6.9",
          "oracle:mysql:5.6.10",
          "oracle:mysql:5.6.11",
          "oracle:mysql:5.6.12",
          "oracle:mysql:5.6.13",
          "oracle:mysql:5.6.14",
          "oracle:mysql:5.6.15",
          "oracle:mysql:5.6.16"
        ]
      }],
      "CVE-2019-1694" => [{
        "id" => "CVE-2019-1694",
        "summary" => "A vulnerability in the TCP processing engine of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS) condition. The vulnerability is due to the improper handling of TCP traffic. An attacker could exploit this vulnerability by sending a specific sequence of packets at a high rate through an affected device. A successful exploit could allow the attacker to temporarily disrupt traffic through the device while it reboots.",
        "cwe" => "CWE-399",
        "published_at" => "2019-05-03 15:29:00 UTC",
        "updated_at" => "2019-05-07 16:50:00 UTC",
        "cvss" => {
          "access_vector" => "NETWORK",
          "access_complexity" => "LOW",
          "authentication" => "NONE",
          "confidentiality_impact" => "NONE",
          "integrity_impact" => "NONE",
          "availability_impact" => "COMPLETE",
          "base_score" => 7.8,
          "vector" => "AV:N/AC:L/Au:N/C:N/I:N/A:C"
        },
        "cvssv3" => {
          "attack_vector" => "NETWORK",
          "attack_complexity" => "LOW",
          "privileges_required" => "NONE",
          "user_interaction" => "NONE",
          "scope" => "CHANGED",
          "confidentiality_impact" => "NONE",
          "integrity_impact" => "NONE",
          "availability_impact" => "HIGH",
          "base_score" => 8.6,
          "base_severity" => "HIGH",
          "vector" => "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"
        },
        "references" => [
          {"href" => "http://www.securityfocus.com/bid/108160"},
          {"href" => "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-frpwrtd-dos"}
        ],
        "cpes_affected" => [
          "cisco:adaptive_security_appliance_software",
          "cisco:firepower_threat_defense"
        ],
        "cpes" => [
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
        ],
        "cpes_with_version" => [
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
      }]
    }

    unknown_good_cves = [
      "CVE-2015-0599",
    ]

    invalid_cves = [
      "badrequests",
    ]

    it_behaves_like "a good parameter handler", url, good_cves, unknown_good_cves, invalid_cves
  end

  describe "/v1/cpe/:cpe_str" do
    url = "/v1/cpe/"
    good_cpes = {
      "apache:camel" => ['CVE-2014-0002', 'CVE-2014-0003'],
      "apache:CAMEL" => ['CVE-2014-0002', 'CVE-2014-0003'],
      "cisco:adaptive_security_appliance_software" => ["CVE-2019-1694"],
      "mariadb:mariadb" => ["CVE-2014-0001"]
    }

    unknown_good_cpes = [
      "cisco:ios"
    ]

    invalid_cpes = [
      "bad$requests+",
      "mariadb:mariadb,bad$request+",
      "bad$request+,mariadb:mariadb",
      "apache:camel:2.11.3",
      "mariadb:mariadb,apache:camel:2.11.3"
    ]

    it_behaves_like "a good parameter handler", url, good_cpes, unknown_good_cpes, invalid_cpes
  end

  describe "/v1/cpe" do
    url = "/v1/cpe"
    expected_results = [
      "apache:camel",
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

    it_behaves_like "good response results", url, expected_results
  end

  describe "/v1/cpe_with_version/:cpe_str" do
    url = "/v1/cpe_with_version/"
    good_cpes = {
      "apache:camel:1.0.0" => ["CVE-2014-0002", "CVE-2014-0003"],
      "cisco:adaptive_security_appliance_software,cisco:asa_5505:-,cisco:asa_5510:-" => ['CVE-2019-1694']
    }

    unknown_good_cpes = [
      "cisco:ios:16.4t",
    ]

    invalid_cpes = [
      "mariadb:mariadb,bad$request+",
      "bad$request+,mariadb:mariadb",
      "apache:camel:2.11.3,bad$request+",
      "bad$request+,apache:camel:2.11.3"
    ]

    it_behaves_like "a good parameter handler", url, good_cpes, unknown_good_cpes, invalid_cpes
  end

  describe "/v1/cpes_affected/:cpe_str" do
    url = "/v1/cpes_affected/"
    good_cpes = {
      "apache:camel,microsoft:edge" => ["CVE-2014-0002","CVE-2014-0003","CVE-2017-0002","CVE-2017-0010","CVE-2017-0011","CVE-2017-0012","CVE-2017-0015"],
      "cisco:adaptive_security_appliance_software,cisco:firepower_threat_defense" => ['CVE-2019-1694']
    }

    unknown_good_cpes = [
      "cisco:ios",
    ]

    invalid_cpes = [
      "mariadb:mariadb,bad$request+",
      "bad$request+,mariadb:mariadb",
      "apache:camel:2.11.3,bad$request+",
      "bad$request+,apache:camel:2.11.3"
    ]

    it_behaves_like "a good parameter handler", url, good_cpes, unknown_good_cpes, invalid_cpes
  end

  describe "/v1/cpes_affected" do
    url = "/v1/cpes_affected"
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

    it_behaves_like "good response results", url, expected_results
  end

  describe "/v1/cpe_with_version" do
    url = "/v1/cpe_with_version"
    expected_results = [
      "apache:camel",
      "apache:camel:1.0.0",
      "apache:camel:1.1.0",
      "apache:camel:1.2.0",
      "apache:camel:1.3.0",
      "apache:camel:1.4.0",
      "apache:camel:1.5.0",
      "apache:camel:1.6.0",
      "apache:camel:1.6.1",
      "apache:camel:1.6.2",
      "apache:camel:1.6.3",
      "apache:camel:1.6.4",
      "apache:camel:2.0.0",
      "apache:camel:2.1.0",
      "apache:camel:2.10.0",
      "apache:camel:2.10.1",
      "apache:camel:2.10.2",
      "apache:camel:2.10.3",
      "apache:camel:2.10.4",
      "apache:camel:2.10.5",
      "apache:camel:2.10.6",
      "apache:camel:2.10.7",
      "apache:camel:2.11.0",
      "apache:camel:2.11.1",
      "apache:camel:2.11.2",
      "apache:camel:2.12.0",
      "apache:camel:2.12.1",
      "apache:camel:2.12.2",
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
      "cisco:firepower_threat_defense",
      "mariadb:mariadb",
      "microsoft:edge",
      "microsoft:edge:-",
      "microsoft:excel:2007",
      "microsoft:excel_viewer",
      "microsoft:internet_explorer:10",
      "microsoft:internet_explorer:11",
      "microsoft:internet_explorer:9",
      "microsoft:office:2010",
      "microsoft:office_compatibility_pack",
      "microsoft:sharepoint_enterprise_server:2016",
      "microsoft:sharepoint_server:2007",
      "microsoft:windows_10",
      "microsoft:windows_10:-",
      "microsoft:windows_10:1511",
      "microsoft:windows_10:1607",
      "microsoft:windows_7",
      "microsoft:windows_7:-",
      "microsoft:windows_8.1",
      "microsoft:windows_rt_8.1",
      "microsoft:windows_server_2008",
      "microsoft:windows_server_2008:-",
      "microsoft:windows_server_2008:r2",
      "microsoft:windows_server_2012:-",
      "microsoft:windows_server_2012:r2",
      "microsoft:windows_server_2016",
      "microsoft:windows_server_2016:-",
      "microsoft:windows_vista",
      "microsoft:windows_vista:-",
      "microsoft:word:2016",
      "mysql:mysql:5.5.0",
      "mysql:mysql:5.5.1",
      "mysql:mysql:5.5.2",
      "mysql:mysql:5.5.3",
      "mysql:mysql:5.5.4",
      "mysql:mysql:5.5.5",
      "mysql:mysql:5.5.6",
      "mysql:mysql:5.5.7",
      "mysql:mysql:5.5.8",
      "mysql:mysql:5.5.9",
      "oracle:mysql:5.5.10",
      "oracle:mysql:5.5.11",
      "oracle:mysql:5.5.12",
      "oracle:mysql:5.5.13",
      "oracle:mysql:5.5.14",
      "oracle:mysql:5.5.15",
      "oracle:mysql:5.5.16",
      "oracle:mysql:5.5.17",
      "oracle:mysql:5.5.18",
      "oracle:mysql:5.5.19",
      "oracle:mysql:5.5.20",
      "oracle:mysql:5.5.21",
      "oracle:mysql:5.5.22",
      "oracle:mysql:5.5.23",
      "oracle:mysql:5.5.24",
      "oracle:mysql:5.5.25",
      "oracle:mysql:5.5.26",
      "oracle:mysql:5.5.27",
      "oracle:mysql:5.5.28",
      "oracle:mysql:5.5.29",
      "oracle:mysql:5.5.30",
      "oracle:mysql:5.5.31",
      "oracle:mysql:5.5.32",
      "oracle:mysql:5.5.33",
      "oracle:mysql:5.5.34",
      "oracle:mysql:5.5.35",
      "oracle:mysql:5.5.36",
      "oracle:mysql:5.6.0",
      "oracle:mysql:5.6.1",
      "oracle:mysql:5.6.10",
      "oracle:mysql:5.6.11",
      "oracle:mysql:5.6.12",
      "oracle:mysql:5.6.13",
      "oracle:mysql:5.6.14",
      "oracle:mysql:5.6.15",
      "oracle:mysql:5.6.16",
      "oracle:mysql:5.6.2",
      "oracle:mysql:5.6.3",
      "oracle:mysql:5.6.4",
      "oracle:mysql:5.6.5",
      "oracle:mysql:5.6.6",
      "oracle:mysql:5.6.7",
      "oracle:mysql:5.6.8",
      "oracle:mysql:5.6.9",
      "redhat:enterprise_linux:5",
      "redhat:enterprise_linux:6.0",
      "redhat:enterprise_linux_desktop:5.0",
      "redhat:enterprise_linux_desktop:6.0",
      "redhat:enterprise_linux_server:6.0",
      "redhat:enterprise_linux_workstation:6.0"
    ]

    it_behaves_like "good response results", url, expected_results
  end

end
