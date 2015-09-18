module CVEServer
  module NVD
    # CVEServer::NVD::Cvss provides an easy way to calculate a vector
    # using the metrics from the NVD reports.
    class Cvss
      def initialize(cvss)
        @cvss = cvss || {}
        @cvss = keys_to_sym!
      end

      def to_hash
        @cvss.merge!(vector: raw_vector) if valid_vector?
        @cvss.to_hash
      end

      protected

      def keys_to_sym!
        @cvss.keys.each_with_object({}) { |k, h| h[k.to_sym] = @cvss[k]; h }
      end

      def raw_vector
        metrics_map.collect do |k, abbrev|
          [abbrev, @cvss[k.to_sym].to_s.slice(0).upcase].join(':')
        end.join('/')
      end

      def valid_vector?
        valid_metrics? && valid_score?
      end

      def valid_metrics?
        metrics_map.keys.none? { |k| @cvss[k.to_sym].nil? }
      end

      def valid_score?
        @cvss[:score].to_f.between?(0.0, 10.0)
      end

      def metrics_map
        {
          access_vector: 'AV',
          access_complexity: 'AC',
          authentication: 'Au',
          confidentiality_impact: 'C',
          integrity_impact: 'I',
          availability_impact: 'A'
        }
      end
    end
  end
end
