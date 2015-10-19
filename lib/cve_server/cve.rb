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

    def self.all_cpe_equal(cpe)
      all(cpes: { '$all': [/^cpe:\/\w:#{cpe}$/i] }).collect do |h|
        h['id']
      end.uniq.sort
    end

    def self.all_cpes_equal(cpes)
      cpes.split(",").collect do |cpe|
        self.all_cpe_equal(cpe)
      end.flatten.uniq.sort
    end

    def self.reduce_cpes
      map_reduce(mapper, reducer, map_reducer_opts).count
    end

    def self.mapper
      %q(
        function() {
          var application_names = [];
          this.cpes.forEach(function(raw_cpe, index) {
            var re = /^cpe:\/\w:?([a-z0-9_\%\~\.\-\:]*)/;
            var cpe = raw_cpe.match(re)[1];
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

    def self.map_reducer_opts
      { out: { replace: 'cpes' }, raw: true }
    end
  end
end
