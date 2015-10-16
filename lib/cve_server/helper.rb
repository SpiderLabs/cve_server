module CVEServer
  module Helper
    module_function

    def valid_cve?(cve)
      # https://cve.mitre.org/cve/identifiers/syntaxchange.html
      cve.match(/^CVE-\d{4}-\d{1,7}$/i)
    end

    def valid_cpe?(cpe)
      cpe.match(/^[a-z0-9_\%\~\.\-\:]+$/i)
    end

    def valid_cpes?(cpes)
      cpes.split(",").all? { |cpe| valid_cpe?(cpe) }
    end

  end
end
