$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'cve_server'

@config = CVEServer::Boot.config

directory   @config.root
rackup      File.join(@config.root, 'config.ru')
environment @config.env
daemonize   @config.env == 'production'

pid_dir =  File.join(@config.root, 'tmp', 'pids')
Dir.mkdir pid_dir unless Dir.exists? pid_dir

pidfile     File.join(pid_dir, 'puma.pid')
state_path  File.join(pid_dir, 'puma.state')
stdout_redirect File.join(@config.root, 'log', 'puma.stdout.log'), File.join(@config.root, 'log', 'puma.stderr.log')

quiet

threads 0, 16

socket_dir =  File.join(@config.root, 'tmp','sockets')
Dir.mkdir socket_dir unless Dir.exists? socket_dir
bind 'tcp://0.0.0.0:9292'
bind "unix://#{socket_dir}/puma.sock?umask=0111"
