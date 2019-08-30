require 'cve_server/db/document'

module CVEServer
  # CVEServer::Cpe is a module to abstract the database table/collection
  # to store and read the CPEs.
  class Cpe
    include CVEServer::DB::Document
    collection_name :cpes

    def self.all
      super.distinct('_id').sort
    end
  end
end
