module CVEServer
  module DB
    # CVEServer::DB::Connection implements the functionality for
    # the database connection handling
    class Connection
      attr_reader :adapter, :options
      attr_accessor :db

      def initialize(config)
        @adapter = config.db_adapter
        @options = config.db_options
        @db = open
      end

      def open?
        case adapter
        when 'mongo' then !db.nil?
        end
      end

      private

      def open
        case adapter
        when 'mongo' then mongo_connection
        else abort "#{adapter} is not supported"
        end
      end

      def mongo_connection
        require adapter
        host_port = [[options['host'], options['port']].join(':')]
        database = { database: options['database'] }
        ::Mongo::Logger.logger.level = Logger::WARN
        ::Mongo::Client.new(host_port, database)
      end
    end
  end
end
