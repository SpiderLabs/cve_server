module CVEServer
  module Helper
    module_function

    def valid_cve?(cve)
      # https://cve.mitre.org/cve/identifiers/syntaxchange.html
      cve.match(/^CVE-\d{4}-\d{1,7}$/i)
    end

    def valid_cpe?(cpe)
      cpe.match(/^[a-z0-9_\%\~\.\-]+(:[a-z0-9_\%\~\.\-]+){0,1}$/i)
    end
  end
end
