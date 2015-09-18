require 'cve_server/db/document'

module CVEServer
  # CVEServer::Cve is a module to abstract the database table/collection
  # to store and read the CVEs.
  class Cpe
    include CVEServer::DB::Document
    collection_name :cpes

    def self.all
      super.collect {|cpe| cpe['_id']}.sort
    end
  end
end
