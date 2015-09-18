$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'cve_server/app'

run CVEServer::App
