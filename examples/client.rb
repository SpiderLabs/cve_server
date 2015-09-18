=begin

Ruby Implementation

Examples:
  client = Client.new("127.0.0.1")
        or
  client = Client.new("127.0.0.1", 8080)
        or
  client = Client.new("127.0.0.1", 443, "https")

  # Get all CPEs defined
  cpes = client.get_all_cpes()

  # Get all CVEs per CPE
  cves = client.get_cves_per_cpe("apache:http_server")

  # Get details for CVE
  cve_hash = client.get_details_per_cve("CVE-2007-5000")

=end

require 'json'
require 'net/http'

class Client
  def initialize(ip, port = 80, scheme = "http")
    @server_url = "#{scheme}://#{ip}:#{port}/v1"
  end

  def get_all_cpes
    return json_from_url("#{@server_url}/cpe")
  end

  def get_cves_per_cpe(cpe)
    return json_from_url("#{@server_url}/cpe/#{cpe}")
  end

  def get_details_per_cve(cve)
    return json_from_url("#{@server_url}/cve/#{cve}")
  end

  private
  def json_from_url(url_str)
    return JSON.parse(Net::HTTP.get(URI.parse(url_str)))
  end
end