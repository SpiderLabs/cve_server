require 'cve_server/nvd/cvss'
module CVEServer
  module NVD
    # CVEServer::NVD::Entry provides an easy way to parse entries from the
    # reports from the National CVEServererability Database.
    #
    # https://nvd.nist.gov/download.cfm
    class Entry
      def initialize(entry)
        @entry = entry
      end

      def to_hash
        {
          id: @entry['id'],
          summary: xpath_content('.//vuln:summary'),
          cwe: cwe_id,
          published_at: xpath_content('.//vuln:published-datetime'),
          updated_at: xpath_content('.//vuln:last-modified-datetime'),
          cvss: CVEServer::NVD::Cvss.new(cvss).to_hash,
          references: references,
          cpes: cpes,
          cpes_with_version: cpes_with_version
        }
      end

      private

      def xpath_content(path, node = @entry)
        node.xpath(path)[0].content unless node.xpath(path)[0].nil?
      end

      def cwe_id
        cwe = @entry.xpath('.//vuln:cwe')[0]
        cwe['id'] unless cwe.nil?
      end

      def cvss
        path = './/cvss:base_metrics/cvss:*'
        @entry.search(path).each_with_object({}) do |cvss, h|
          h[cvss.name.gsub(/-/, '_').to_sym] = cvss.content
          h
        end
      end

      def references
        @entry.xpath('.//vuln:references').collect do |node|
          {
            type: node['reference_type'],
            name: xpath_content('.//vuln:source', node),
            href: node.xpath('.//vuln:reference')[0]['href'],
            content: xpath_content('.//vuln:reference', node)
          }
        end
      end

      def cpes
        path = './/vuln:vulnerable-software-list/vuln:product'
        full_cpes = remove_cpe_text(@entry.xpath(path).collect(&:content))
        full_cpes.map {|cpe| cpe.split(":")[0..1].join(":")}.uniq
      end

      def cpes_with_version
        path = './/vuln:vulnerable-software-list/vuln:product'
        remove_cpe_text(@entry.xpath(path).collect(&:content))
      end

      def remove_cpe_text(cpes)
        cpes.map {|cpe| cpe.gsub(/^cpe:\/\w:/,"")}
      end
    end
  end
end
