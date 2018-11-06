require 'yaml'
require 'bundler/setup'

ENV['RACK_ENV'] ||= 'development'
Bundler.require(:default, ENV['RACK_ENV'].to_sym)

module CVEServer
  # CVEServer::Config helps to handle the configuration options
  class Config
    attr_reader :env, :root, :path,  :db_settings

    def initialize
      @env = ENV['RACK_ENV']
      @root = File.join(File.dirname(__FILE__), '..', '..')
      @path = File.join(root, 'config', 'database.yml')
    end

    def db_adapter
      db_settings['adapter']
    end

    def db_options
      db_settings.select { |k, _v| k != 'adapter' }
    end

    def raw_data_path
      if env == 'test'
        File.join(root, 'spec', 'fixtures', 'nvd_data')
      else
        File.join(root, 'nvd_data')
      end
    end

    def cpe_exceptions
      begin
        YAML.load_file(File.join(root, 'config', 'cpe_exceptions.yml')) || []
      rescue Errno::ENOENT
        []
      end
    end

    private

    def db_settings
      @db_settings ||= YAML.load(File.read(path))[env]
    end
  end
end
