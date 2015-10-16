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

  def individual_cpes
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
      'splunk:splunk:6.2.0::~~light~~~',
      'microsoft:windows_server_2012:r2::~~~x64~~',
      'microsoft:windows_8.1:-',
      'cisco:ios:15.3%28100%29m',
      'cisco:ios:15.4%282%29t1',
      'novell:suse_linux_for_vmware:11.0:sp3:~~server~~~',
      'novell:suse_linux_sdk:11.0:sp3',
      'oracle:berkeley_db:12.1.6.0.35'
    ]
  end

  def invalid_individual_cpes
    [
      '*:*:*',
      'amazon:*',
      '*:openbsd',
      '\*:linux',
      '%\?pple:mac_os_x',
    ]
  end

  def bulk_cpes
    [
      '1two:livre_d_or,1und1:1%261_online_storage',
      'amarok:amarok,amarok:web_frontend',
      'apple:mac_os,apple:mac_os_runtime_for_java',
      'cisco:nac_manager,cisco:netflow_collection_engine',
    ]
  end

  def invalid_bulk_cpes
    [
      '1two:livre_d_or,*:*:*',
      'apple:mac_os,amazon:*',
      'amarok:amarok,*:openbsd',
      'cisco:nexus_1000v,\*:linux',
      '%\?pple:mac_os_x,amarok:amarok',
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
    describe '#valid_cpe?' do
      HelperSpec.individual_cpes.each do |cpe|
        it "should validates '#{cpe}'" do
          expect(@module.valid_cpe?(cpe)).not_to be eq(nil)
        end
      end

      HelperSpec.invalid_individual_cpes.each do |cpe|
        it "should not validates '#{cpe}'" do
          expect(@module.valid_cpe?(cpe)).to eq(nil)
        end
      end
    end

    describe '#valid_cpes?' do
      HelperSpec.bulk_cpes.each do |cpe|
        it "should validates '#{cpe}'" do
          expect(@module.valid_cpes?(cpe)).not_to be eq(nil)
        end
      end

      HelperSpec.invalid_bulk_cpes.each do |cpe|
        it "should not validates '#{cpe}'" do
          expect(@module.valid_cpes?(cpe)).to eq(nil)
        end
      end
    end
  end
end
