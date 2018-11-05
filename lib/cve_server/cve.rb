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

    def self.all_cpe_with_version_equal(cpe)
      all(cpes_with_version: /^#{Regexp.escape(cpe)}$/i).collect do |h|
        h['id']
      end.uniq.sort
    end

    def self.reduce_cpes
      total_count = 0
      ["cpes", "cpes_with_version"].each do |field|
        total_count += map_reduce(mapper(field), reducer, map_reducer_opts(field)).count
      end

      return total_count
    end

    def self.mapper(field)
      %Q(
        function() {
          var application_names = [];
          this.#{field}.forEach(function(cpe, index) {
            if ((application_names.indexOf(cpe) < 0) && (cpe))
              application_names.push(cpe);
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
