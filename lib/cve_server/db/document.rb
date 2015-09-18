require 'cve_server/boot'
module CVEServer
  # CVEServer::DB::Document adds the database connection and the specific
  # code for each database into a class
  module DB
    module Document
      extend self

      def included(base)
        base.extend(CVEServer::Boot)
        adapter = CVEServer::Boot.config.db_adapter
        require "cve_server/db/#{adapter}"
        klass = adapter.capitalize
        if CVEServer::DB.const_defined?(klass)
          base.extend(CVEServer::DB.const_get(klass))
        else
          abort "The #{adapter} is not supported"
        end
      end
    end
  end
end
