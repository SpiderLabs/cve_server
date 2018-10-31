require 'cve_server/nvd/cvss'
require 'time'

module CVEServer
  module NVD
    module JSON
      class Entry
        def initialize(entry)
          @entry = entry
        end

        def to_hash
          {
            id: id,
            summary: summary,
            cwe: cwe,
            published_at: published_at,
            updated_at: updated_at,
            cvss: cvssv2,
            cvssv3: cvssv3,
            references: references,
            cpes: cpes,
            cpes_with_version: cpes_with_version
          }
        end

        def id
          cve = attribute('cve', 'CVE_data_meta')
          cve['ID'] if cve.is_a?(Hash) && cve.key?('ID')
        end

        def summary
          descr = attribute('cve', 'description')
          if descr.is_a?(Hash) && descr.key?('description_data')
            descr['description_data'].collect { |data| data['value'] }.join("\n")
          end
        end

        def cwe
          problemtype = attribute('cve', 'problemtype')
          if problemtype.is_a?(Hash) && problemtype.key?('problemtype_data')
            problemtype['problemtype_data'].collect do |data|
              data['description'].collect { |e| e['value'] }
            end.flatten.join
          end
        end

        def published_at
          time_at('publishedDate')
        end

        def updated_at
          time_at('lastModifiedDate')
        end

        def cvssv2
          base_metric = attribute('impact', 'baseMetricV2')
          if base_metric.is_a?(Hash) && base_metric.key?('cvssV2')
            cvss = base_metric['cvssV2'] || {}
            v2 = cvss.each_with_object({}) { |e, h| h[normalize_key(e[0])] = e[1] }
            v2.delete('vector_string')
            CVEServer::NVD::Cvss.new(v2).to_hash
          end
        end

        def cvssv3
          base_metric = attribute('impact', 'baseMetricV3')
          if base_metric.is_a?(Hash) && base_metric.key?('cvssV3')
            cvss = base_metric['cvssV3'] || {}
            v3 = cvss.each_with_object({}) { |e, h| h[normalize_key(e[0]).to_sym] = e[1] }
            v3[:vector] = v3.delete(:vector_string) if v3.key?(:vector_string)
            v3
          end
        end

        def references
          references = attribute('cve', 'references')
          if references.is_a?(Hash) && references.key?('reference_data')
            references['reference_data'].collect { |e| { href: e['url'] } }
          end
        end

        def cpes
          cpes_with_version.map { |cpe| cpe.split(':')[0..1].join(':') }.uniq
        end

        def cpes_with_version
          full_cpes.map { |cpe| cpe.gsub(/^cpe:\/\w:/, '') }.uniq
        end

        private
        def attribute(node, attr)
          @entry[node][attr] if @entry.key?(node) && @entry[node].key?(attr)
        end

        def time_at(attr)
          Time.parse(@entry[attr]) if @entry.key?(attr)
        end

        def normalize_key(key)
          key.sub(/[A-Z]/) { |chr| '_' + chr.downcase }
        end

        def full_cpes
          nodes = attribute('configurations', 'nodes') || []
          nodes.collect do |e|
            cpe_match = e.fetch('cpe_match', [])
            next if cpe_match.empty?
            cpe_match.map { |cpe| cpe.dig('cpe22Uri') || cpe.dig('cpe23Uri') }
          end.compact.flatten
        end
      end
    end
  end
end
