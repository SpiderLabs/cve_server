require 'cve_server/db/document'

module CVEServer
  # CVEServer::Cpe is a module to abstract the database table/collection
  # to store and read the CPEs that have version information with it.
  class CpeWithVersion
    include CVEServer::DB::Document
    collection_name :cpes_with_version

    def self.all
      super.distinct('_id').sort
    end
  end
end
