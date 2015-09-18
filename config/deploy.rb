lock '3.4.0'
set :application, 'cve_server'
set :repo_url, 'git@github.com:SpiderLabs/cve_server.git'
set :branch, 'master' # Default branch is :master
set :deploy_to, '/home/deployer/cve_server'
set :stage, :production
set :pty, false
set :linked_dirs, fetch(:linked_dirs, []).push('nvd_data', 'log', 'tmp')

set :puma_rackup, -> { File.join(current_path, 'config.ru') }
set :puma_state, "#{shared_path}/tmp/pids/puma.state"
set :puma_pid, "#{shared_path}/tmp/pids/puma.pid"
set :puma_bind, "unix://#{shared_path}/tmp/sockets/puma.sock"    #accept array for multi-bind
set :puma_default_control_app, "unix://#{shared_path}/tmp/sockets/pumactl.sock"
set :puma_conf, "#{shared_path}/puma.rb"
set :puma_access_log, "#{shared_path}/log/puma_access.log"
set :puma_error_log, "#{shared_path}/log/puma_error.log"
set :puma_role, :app
set :puma_env, fetch(:rack_env, fetch(:rails_env, 'production'))
set :puma_threads, [0, 16]
set :puma_workers, 0
set :puma_worker_timeout, nil
set :puma_init_active_record, false
set :puma_preload_app, true

namespace :deploy do

  namespace :symlink do
    desc 'Symlink linked directories'
    task :linked_dirs do
      next unless any? :linked_dirs
      on release_roles :all do
        execute :mkdir, '-pv', linked_dir_parents(shared_path)
        execute :mkdir, '-pv', shared_path.join('tmp/sockets')
        execute :mkdir, '-pv', shared_path.join('tmp/pids')

        fetch(:linked_dirs).each do |dir|
          target = release_path.join(dir)
          source = shared_path.join(dir)
          unless test "[ -L #{target} ]"
            if Dir.exist?(target)
              execute :rm, '-rf', target
            end
            execute :ln, '-s', source, target
          end
        end
      end
    end
  end

  desc 'download the nvd reports'
  task :download_nvd_reports do
    on fetch(:bundle_servers) do
      within release_path do
        with fetch(:bundle_env_variables, {}) do
          execute :bundle, 'exec', './bin/nvd_downloader'
        end
      end
    end
  end

  desc 'reload the database with seed data'
  task :seed do
    on fetch(:bundle_servers) do
      within release_path do
        with fetch(:bundle_env_variables, {}) do
          execute :bundle, 'exec', "./bin/seed RACK_ENV=#{fetch(:rack_env,{})}"
        end
      end
    end
  end
end
