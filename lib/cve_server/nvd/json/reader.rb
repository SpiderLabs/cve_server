require 'json'
require 'cve_server/nvd/json/entry'

module CVEServer
  module NVD
    module JSON
      class Reader
        def initialize(input)
          @json = ::JSON.parse(input)
        end

        def all_entries
          @json['CVE_Items']
        end

        def all_cve
          all_entries.collect do |entry|
            CVEServer::NVD::JSON::Entry.new(entry).to_hash
          end
        end

        def each_cve(&blk)
          all_cve.each(&blk)
        end
      end
    end
  end
end
