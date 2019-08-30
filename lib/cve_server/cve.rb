require 'cve_server/db/document'

module CVEServer
  # CVEServer::Cve is a module to abstract the database table/collection
  # to store and read the CVEs.
  class Cve
    include CVEServer::DB::Document

    collection_name :cves

    def self.find(cve)
      remove_id(super(id: cve))
    end

    def self.all(pattern={})
      super(pattern).map {|entry| remove_id(entry) }
    end

    def self.all_cpes_equal(cpes)
      cpes.split(",").collect do |cpe|
        self.all_cpe_equal(cpe)
      end.flatten.uniq.sort
    end

    def self.all_cpe_equal(cpe)
      all(cpes: /^#{Regexp.escape(cpe)}$/i).collect do |h|
        h['id']
      end.uniq.sort
    end

    def self.all_cpes_with_version_equal(cpes)
      cpes.split(",").collect do |cpe|
        self.all_cpe_with_version_equal(cpe)
      end.flatten.uniq.sort
    end

    def self.all_cpes_affected(cpes = nil)
      result = if cpes.nil?
                 all.map { |h| h['cpes_affected'] }
               else
                 unless cpes.is_a?(Array) or cpes.is_a?(String)
                   raise TypeError, "'cpes' must be an Array or String"
                 end
                 [cpes].flatten.map do |cpe|
                   all(cpes_affected: /^#{Regexp.escape(cpe.to_s)}$/i).collect do |h|
                     h['id']
                   end
                 end
               end
      result.flatten.compact.uniq.sort
    end

    def self.all_cpe_with_version_equal(cpe)
      all(cpes_with_version: /^#{Regexp.escape(cpe)}$/i).collect do |h|
        h['id']
      end.uniq.sort
    end

    def self.reduce_cpes
      ["cpes", "cpes_with_version"].each do |field|
        map_reduce(mapper(field), reducer, map_reducer_opts(field))
      end
    end

    def self.mapper(field)
      %Q(
        function() {
          var application_names = [];
          this.#{field}.forEach(function(field, index) {
            if ((application_names.indexOf(field) < 0) && (field))
              application_names.push(field);
          });
          for (var i = 0;  i < application_names.length; i++) {
            emit(application_names[i], {count: 1});
          }
        }
      )
    end

    def self.reducer
      %q(
        function(key, values) {
          var res = { count: 0 };
          values.forEach(function(v) { res.count += v.count; });
          return res;
        }
      )
    end

    def self.map_reducer_opts(field)
      { out: { replace: field }, raw: true }
    end

  end
end
