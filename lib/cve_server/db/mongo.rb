module CVEServer
  module DB
    # CVEServer::DB::Mongo contains the code for the mongo queries
    module Mongo
      extend self

      def collection_name(name)
        @collection = name.to_sym
      end

      def find(args)
        db[@collection].find(args).first
      end

      def all(pattern = {})
        db[@collection].find(pattern)
      end

      def all_sorted_by(attr, pattern={})
        db[@collection].find(pattern).sort(attr.to_sym => ::Mongo::Index::ASCENDING)
      end

      def exist?(args)
        db[@collection].find(args).count > 0
      end

      def create(args)
        db[@collection].insert_one(args)
      end

      def bulk_create(data)
        inserts = data.reduce([]) do |ops, chunk|
          ops << { :insert_one => chunk }
        end
        db[@collection].bulk_write(inserts, ordered: true)
      end

      def drop_all
        db[@collection].drop
      end

      def map_reduce(mapper, reducer, options = {})
        db[@collection].find({}, no_cursor_timeout: true).map_reduce(mapper, reducer, options).execute
      end

      def remove_id(record)
        record.delete_if { |k, _| k == '_id' } if record.is_a? Hash
      end
    end
  end
end
