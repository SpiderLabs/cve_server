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
      "CVE-2014-0001" => {"id"=>"CVE-2014-0001",
                          "summary"=>
                          "Buffer overflow in client/mysql.cc in Oracle MySQL and MariaDB before 5.5.35 allows remote database servers to cause a denial of service (crash) and possibly execute arbitrary code via a long server version string.",
                          "cwe"=>"CWE-119",
                          "published_at"=>"2014-01-31T18:55:04.503-05:00",
                          "updated_at"=>"2014-06-30T13:58:53.547-04:00",
                          "cvss"=>
                           {"score"=>"7.5",
                            "access_vector"=>"NETWORK",
                            "access_complexity"=>"LOW",
                            "authentication"=>"NONE",
                            "confidentiality_impact"=>"PARTIAL",
                            "integrity_impact"=>"PARTIAL",
                            "availability_impact"=>"PARTIAL",
                            "source"=>"http://nvd.nist.gov",
                            "generated_on_datetime"=>"2014-02-02T20:10:48.000-05:00",
                            "vector"=>"AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                          "references"=>
                           [{"type"=>"PATCH",
                             "name"=>"CONFIRM",
                             "href"=>"http://bazaar.launchpad.net/~maria-captains/maria/5.5/revision/2502.565.64",
                             "content"=>"http://bazaar.launchpad.net/~maria-captains/maria/5.5/revision/2502.565.64"},
                            {"type"=>"UNKNOWN", "name"=>"CONFIRM", "href"=>"https://mariadb.com/kb/en/mariadb-5535-changelog/", "content"=>"https://mariadb.com/kb/en/mariadb-5535-changelog/"},
                            {"type"=>"UNKNOWN", "name"=>"CONFIRM", "href"=>"https://bugzilla.redhat.com/show_bug.cgi?id=1054592", "content"=>"https://bugzilla.redhat.com/show_bug.cgi?id=1054592"},
                            {"type"=>"UNKNOWN", "name"=>"OSVDB", "href"=>"http://www.osvdb.org/102714", "content"=>"102714"},
                            {"type"=>"UNKNOWN", "name"=>"MANDRIVA", "href"=>"http://www.mandriva.com/security/advisories?name=MDVSA-2014:029", "content"=>"MDVSA-2014:029"},
                            {"type"=>"UNKNOWN", "name"=>"REDHAT", "href"=>"http://rhn.redhat.com/errata/RHSA-2014-0189.html", "content"=>"RHSA-2014:0189"},
                            {"type"=>"UNKNOWN", "name"=>"REDHAT", "href"=>"http://rhn.redhat.com/errata/RHSA-2014-0186.html", "content"=>"RHSA-2014:0186"},
                            {"type"=>"UNKNOWN", "name"=>"REDHAT", "href"=>"http://rhn.redhat.com/errata/RHSA-2014-0173.html", "content"=>"RHSA-2014:0173"},
                            {"type"=>"UNKNOWN", "name"=>"REDHAT", "href"=>"http://rhn.redhat.com/errata/RHSA-2014-0164.html", "content"=>"RHSA-2014:0164"},
                            {"type"=>"UNKNOWN", "name"=>"OSVDB", "href"=>"http://osvdb.org/102713", "content"=>"102713"}],
                          "cpes"=>["mysql:mysql", "mariadb:mariadb"],
                          "cpes_with_version"=>["mysql:mysql", "mariadb:mariadb:5.5.34"]
                         },
      "CVE-2015-0593" => {"id"=>"CVE-2015-0593",
                          "summary"=>
                          "The Zone-Based Firewall implementation in Cisco IOS 12.4(122)T and earlier does not properly manage session-object structures, which allows remote attackers to cause a denial of service (device reload) via crafted network traffic, aka Bug ID CSCul65003.",
                          "cwe"=>"CWE-399",
                          "published_at"=>"2015-02-12T21:59:09.063-05:00",
                          "updated_at"=>"2015-02-18T22:01:11.633-05:00",
                          "cvss"=>
                           {"score"=>"7.1",
                            "access_vector"=>"NETWORK",
                            "access_complexity"=>"MEDIUM",
                            "authentication"=>"NONE",
                            "confidentiality_impact"=>"NONE",
                            "integrity_impact"=>"NONE",
                            "availability_impact"=>"COMPLETE",
                            "source"=>"http://nvd.nist.gov",
                            "generated_on_datetime"=>"2015-02-18T10:14:59.087-05:00",
                            "vector"=>"AV:N/AC:M/Au:N/C:N/I:N/A:C"},
                          "references"=>
                           [{"type"=>"VENDOR_ADVISORY",
                             "name"=>"CISCO",
                             "href"=>"https://tools.cisco.com/quickview/bug/CSCul65003",
                             "content"=>"20150209 Cisco IOS Software Zone-Based Firewall Vulnerability"},
                            {"type"=>"UNKNOWN", "name"=>"XF", "href"=>"http://xforce.iss.net/xforce/xfdb/100757", "content"=>"ciscoios-cve20150593-dos(100757)"},
                            {"type"=>"UNKNOWN", "name"=>"BID", "href"=>"http://www.securityfocus.com/bid/72549", "content"=>"72549"},
                            {"type"=>"VENDOR_ADVISORY",
                             "name"=>"CONFIRM",
                             "href"=>"http://tools.cisco.com/security/center/viewAlert.x?alertId=37417",
                             "content"=>"http://tools.cisco.com/security/center/viewAlert.x?alertId=37417"},
                            {"type"=>"VENDOR_ADVISORY",
                             "name"=>"CISCO",
                             "href"=>"http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2015-0593",
                             "content"=>"20150209 Cisco IOS Software Zone-Based Firewall Vulnerability"}],
                          "cpes"=>["cisco:ios"],
                          "cpes_with_version"=>["cisco:ios:15.4%281.12%29t", "cisco:ios:15.4%281.19%29t"]
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

  describe "/v1/cpe/:cpe_str" do
    url = "/v1/cpe/"
    good_cpes = {
      "apache:camel" => ['CVE-2014-0002', 'CVE-2014-0003'],
      "apache:CAMEL" => ['CVE-2014-0002', 'CVE-2014-0003'],
      "cisco:ios" => ["CVE-2015-0592", "CVE-2015-0593"],
      "mariadb:mariadb" => ["CVE-2014-0001"],
      "apache:camel,mariadb:mariadb" => ['CVE-2014-0001', 'CVE-2014-0002', 'CVE-2014-0003'],
    }

    unknown_good_cpes = [
      "oracle:mysql",
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
      "cisco:ios",
      "mariadb:mariadb",
      "mysql:mysql"
    ]

    it_behaves_like "good response results", url, expected_results
  end

  describe "/v1/cpe_with_version/:cpe_str" do
    url = "/v1/cpe_with_version/"
    good_cpes = {
      "apache:camel:2.11.3" => ["CVE-2014-0002", "CVE-2014-0003"],
      "mysql:mysql,apache:camel:2.11.3" => ["CVE-2014-0001", "CVE-2014-0002", "CVE-2014-0003"],
      "cisco:ios:15.4t" => ["CVE-2015-0592"],
      "cisco:ios:15.4t,apache:camel:2.11.3" => ["CVE-2014-0002", "CVE-2014-0003", "CVE-2015-0592"],
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

  describe "/v1/cpe_with_version" do
    url = "/v1/cpe_with_version"
    expected_results = [
      "apache:camel:1.0.0",
      "apache:camel:1.6.1",
      "apache:camel:2.0.0:m1",
      "apache:camel:2.11.3",
      "apache:camel:2.12.0",
      "apache:camel:2.12.2",
      "cisco:ios:15.4%281.12%29t",
      "cisco:ios:15.4%281.19%29t",
      "cisco:ios:15.4%282%29t1",
      "cisco:ios:15.4t",
      "mariadb:mariadb:5.5.34",
      "mysql:mysql",
    ]

    it_behaves_like "good response results", url, expected_results
  end

end
