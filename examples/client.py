"""

Python Implementation

Examples:
  client = Client("127.0.0.1")
        or
  client = Client("127.0.0.1", 8080)
        or
  client = Client("127.0.0.1", 443, "https")

  # Get all CPEs defined
  cpes = client.get_all_cpes()

  # Get all CVEs per CPE
  cves = client.get_cves_per_cpe("apache:http_server")

  # Get details for CVE
  cve_hash = client.get_details_per_cve("CVE-2007-5000")

"""

import json
import urllib2

class Client:
    def __init__(self, ip, port = 80, scheme = "http"):
        self.server_url = scheme + '://' + ip + ':' + str(port) + '/v1'

    def get_all_cpes(self):
        return self.__json_from_url(self.server_url + '/cpe')

    def get_cves_per_cpe(self, cpe):
        return self.__json_from_url(self.server_url + '/cpe/' + cpe)

    def get_details_per_cve(self, cve):
        return self.__json_from_url(self.server_url + '/cve/' + cve)

    def __json_from_url(self, url_str):
        return json.load(urllib2.urlopen(url_str))