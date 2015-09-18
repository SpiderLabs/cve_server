require 'nokogiri'
require 'cve_server/nvd/entry'

module CVEServer
  module NVD
    # CVEServer::NVD::Reader provides an easy way to read the reports
    # (version 2.0) from the National CVEServererability Database.
    #
    # https://nvd.nist.gov/download.cfm
    class Reader
      def initialize(input)
        @doc = Nokogiri::XML(input)
      end

      def all_cve
        @doc.xpath('//xmlns:entry').collect do |entry|
          CVEServer::NVD::Entry.new(entry).to_hash
        end
      end

      def each_cve(&blk)
        all_cve.each(&blk)
      end
    end
  end
end
