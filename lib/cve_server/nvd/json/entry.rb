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
            cpes_affected: cpes_affected,
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
            end.flatten
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
            v2.delete('version')
            CVEServer::NVD::Cvss.new(v2).to_hash
          end
        end

        def cvssv3
          base_metric = attribute('impact', 'baseMetricV3')
          if base_metric.is_a?(Hash) && base_metric.key?('cvssV3')
            cvss = base_metric['cvssV3'] || {}
            v3 = cvss.each_with_object({}) { |e, h| h[normalize_key(e[0]).to_sym] = e[1] }
            v3[:vector] = v3.delete(:vector_string) if v3.key?(:vector_string)
            v3.delete(:version)
            v3
          end
        end

        def references
          references = attribute('cve', 'references')
          if references.is_a?(Hash) && references.key?('reference_data')
            references['reference_data'].collect { |e| { href: e['url'] } }
          end
        end

        # Affected CPEs created using vendor and product name under the "affects" node
        # @return [Array<String>]
        def cpes_affected
          cpes.flatten.uniq
        end

        def cpes
          cpes_with_version.map { |cpe| cpe.split(':')[0..1].join(':') unless cpe.nil? }.uniq
        end

        def cpes_with_version
          cpe_regex = /^cpe:(?:\/|2\.[23]:)[aho]:(?<vendor>[^:]+):(?<product>[^:]+):(?<version>[^:]+)/
          cpe_versionStartIncluding = /versionStartIncluding:(?<versionStartIncluding>[^:]+)/
          cpe_versionStartExcluding = /versionStartExcluding:(?<versionStartExcluding>[^:]+)/
          cpe_versionEndIncluding = /versionEndIncluding:(?<versionEndIncluding>[^:]+)/
          cpe_versionEndExcluding = /versionEndExcluding:(?<versionEndExcluding>[^:]+)/
          full_cpes.map do |cpe|
            if match = cpe.match(cpe_regex)
              cpe_parts = [match[:vendor], match[:product]]
              cpe_parts << match[:version] unless match[:version] == '*'
              cpe_parts << cpe.match(cpe_versionStartIncluding) unless cpe.match(cpe_versionStartIncluding).nil?
              cpe_parts << cpe.match(cpe_versionStartExcluding) unless cpe.match(cpe_versionStartExcluding).nil?
              cpe_parts << cpe.match(cpe_versionEndIncluding) unless cpe.match(cpe_versionEndIncluding).nil?
              cpe_parts << cpe.match(cpe_versionEndExcluding) unless cpe.match(cpe_versionEndExcluding).nil?
              cpe_parts.join(':')
            end
          end.uniq
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

        # Extracts CPEs that may be deeply nested
        # @param [Array]  children Nested CPE nodes
        # @return [Array<String>] Full CPEs
        def nested_cpes(children)
          cpes = []
          children.each do |child|
            if child.has_key?('cpe_match')
              child['cpe_match'].each do |cpe_match|
                cpe_temp = ""
                cpe_temp += cpe_match['cpe23Uri'] if cpe_match.has_key?('cpe23Uri')
                cpe_temp += cpe_match['cpe22Uri'] if cpe_match.has_key?('cpe22Uri')
                cpe_temp += "versionStartIncluding:#{cpe_match['versionStartIncluding']}:" if cpe_match.has_key?('versionStartIncluding')
                cpe_temp += "versionStartExcluding:#{cpe_match['versionStartExcluding']}:" if cpe_match.has_key?('versionStartExcluding')
                cpe_temp += "versionEndIncluding:#{cpe_match['versionEndIncluding']}:" if cpe_match.has_key?('versionEndIncluding')
                cpe_temp += "versionEndExcluding:#{cpe_match['versionEndExcluding']}" if cpe_match.has_key?('versionEndExcluding')
                cpes << cpe_temp
              end
            elsif child.has_key?('children')
              cpes.push *nested_cpes(child['children']).flatten
            end
          end
          cpes
        end

        def full_cpes
          nodes = attribute('configurations', 'nodes') || []
          nested_cpes(nodes)
        end
      end
    end
  end
end
