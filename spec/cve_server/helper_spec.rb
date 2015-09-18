require 'spec_helper'
require 'cve_server/helper'

module HelperSpec
  module_function

  def cves
    [
      'CVE-2011-1529',
      'CVE-2011-1530',
      'CVE-2011-1624',
      'CVE-2011-1625',
      'CVE-2011-1640',
      'CVE-2011-1737',
      'CVE-2011-1738',
      'CVE-2012-0814',
      'cve-2013-2125',
      'cve-2013-4548',
      'CVE-2014-1692',
      'CVE-2014-2532',
      'CVE-2014-2653',
      'CVE-2014-7250',
      'CVE-2014-9278',
      'CVE-2014-9424'
    ]
  end

  def invalid_cves
    [
      'CVE20111529',
      'CVE_2011_1530',
      'CVE*2011*1624',
      'CVE?2011?1624',
      'CVE-\d{4}-\d{4}',
    ]
  end

  def cpes
    [
      '1two:livre_d_or',
      '1und1:1%261_online_storage',
      '20_20_applications:20_20_auto_gallery',
      'amarok:amarok',
      'amarok:web_frontend',
      'amateras:amateras_sns',
      'apple:mac_os',
      'apple:mac_os_runtime_for_java',
      'apple:mac_os_x',
      'cisco:nac_manager',
      'cisco:netflow_collection_engine',
      'cisco:network_access_control',
      'cisco:network_admission_control',
      'cisco:network_analysis_module',
      'cisco:network_convergence_system_6000',
      'cisco:network_convergence_system_6008',
      'cisco:network_services_manager',
      'cisco:nexus_1000v',
      'cisco:nexus_2148t_fex_switch',
      'cisco:nexus_2224tp_fex_switch',
      'cisco:nexus_2232pp_fex_switch',
      'cisco:nexus_2232tm_fex_switch',
      'cisco:nexus_2248tp_e_fex_switch',
      'cisco:nexus_2248tp_fex_switch',
    ]
  end

  def invalid_cpes
    [
      '::::::::::::',
      '*:*:*',
      'amazon:*',
      '*:openbsd',
      '\*:linux',
      '%\?pple:mac_os_x',
    ]
  end
end

describe 'CVEServer::Helper' do
  before :all do
    @module = CVEServer::Helper
  end

  describe 'CVE Validations' do
    HelperSpec.cves.each do |cve|
      it "should validates '#{cve}'" do
        expect(@module.valid_cve?(cve)).not_to be eq(nil)
      end
    end

    HelperSpec.invalid_cves.each do |cve|
      it "should not validates '#{cve}'" do
        expect(@module.valid_cve?(cve)).to eq(nil)
      end
    end
  end

  describe 'CPE Validations' do
    HelperSpec.cpes.each do |cpe|
      it "should validates '#{cpe}'" do
        expect(@module.valid_cpe?(cpe)).not_to be eq(nil)
      end
    end

    HelperSpec.invalid_cpes.each do |cpe|
      it "should not validates '#{cpe}'" do
        expect(@module.valid_cpe?(cpe)).to eq(nil)
      end
    end
  end
end
