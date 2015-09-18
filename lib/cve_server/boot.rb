require 'cve_server/config'
require 'cve_server/db/connection'

module CVEServer
  module Boot
    extend self

    def config
      @config ||= CVEServer::Config.new
    end

    def connection
      @conn ||= CVEServer::DB::Connection.new(config)
    end

    def db
      connection.db if connection.open?
    end
  end
end
