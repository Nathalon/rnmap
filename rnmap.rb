# Copyright (C) 2022, Nathalon

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

require 'ostruct'
require 'optparse'
require 'nmap/program'

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end
end

class Rnmap

  Version = "Version: (rnmap 0.0.1), Written by (Nathalon)".green

  def parse_opts(args)
    ARGV << "-h" if ARGV.empty?
    @options = OpenStruct.new
	
    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{__FILE__} [options]"

      # Host Discovery:

      opts.on("--sL", "--list",
        "List Scan - simply list targets to scan") do
        @options.list = :list
      end

      opts.on("--sP", "--ping",
        "Ping Scan - disable port scan") do
        @options.ping = :ping
      end

      opts.on("--Pn", "--skip-discovery",
        "Treat all hosts as online -- skip host discovery") do
        @options.skip_discovery = :skip_discovery
      end

      opts.on("--PS", "--syn-discovery ", String,
         "[portlist]: TCP SYN discovery to given ports") do |syn_discovery|
        @options.syn_discovery = syn_discovery 
      end

      opts.on("--PA", "--ack-discovery ", String,
         "[portlist]: ACK discovery to given ports") do |ack_discovery|
        @options.ack_discovery = ack_discovery 
      end

      opts.on("--PU", "--udp-discovery ", String,
         "[portlist]: UDP discovery to given ports") do |udp_discovery|
        @options.udp_discovery = udp_discovery 
      end

      opts.on("--PY", "--sctp-init-ping ", String,
          "[portlist]: SCTP discovery to given ports") do |sctp_init_ping|
        @options.sctp_init_ping = sctp_init_ping
      end

      opts.on("--PE", "--icmp-echo-disc",
        "ICMP echo") do
        @options.icmp_echo_discovery = :icmp_echo_discovery
      end

      opts.on("--PP", "--icmp-timestamp-disc",
        "Timestamp request discovery probes") do
        @options.icmp_timestamp_discovery = :icmp_timestamp_discovery
      end

      opts.on("--PM", "--icmp-netmask-disc",
        "Netmask request discovery probes") do
        @options.icmp_netmask_discovery = :icmp_netmask_discovery
      end

      opts.on("--PO", "--ip-ping",
        "[protocol list]: IP Protocol Ping") do
        @options.ip_ping = :ip_ping
      end

      opts.on("--PR", "--arp-ping",
        "ARP Scan") do
        @options.arp_ping = :arp_ping
      end

      opts.on("--traceroute",
        "Trace hop path to each host") do
        @options.traceroute = :traceroute
      end

      opts.on("--n", "--disable-dns",
        "Never do DNS resolution") do
        @options.disable_dns = :disable_dns
      end

      opts.on("--R", "--enable-dns",
        "Always resolve [default: sometimes]") do
        @options.enable_dns = :enable_dns 
      end

      opts.on("--system-dns",
        "Use OS's DNS resolver") do
        @options.system_dns = :system_dns
      end

      opts.on("--dns-servers ", String,
         "<serv1[,serv2],...>: Specify custom DNS servers") do |dns_servers|
        @options.dns_servers = dns_servers 
      end

      # Port Scanning Techniques:

      opts.on("--sS", "--syn-scan",
        "TCP SYN scan") do
        @options.syn_scan = :syn_scan
      end

      opts.on("--sT", "--connect-scan",
        "Connect() scan") do
        @options.connect_scan = :connect_scan
      end

      opts.on("--sU", "--udp-scan",
        "UDP scan") do
        @options.udp_scan = :udp_scan
      end

      opts.on("--sY", "--sctp-init-scan",
        "SCTP INIT/COOKIE-ECHO scans") do
        @options.sctp_init_scan = :sctp_init_scan
      end

      opts.on("--sN", "--null-scan",
        "TCP Null scan") do
        @options.null_scan = :null_scan
      end

      opts.on("--sF", "--fin-scan",
        "FIN scan") do
        @options.fin_scan = :fin_scan
      end

      opts.on("--sX", "--xmas-scan",
        "Xmas scan") do
        @options.xmas_scan = :xmas_scan
      end

      opts.on("--sA", "--ack-scan",
        "ACK scan") do
        @options.ack_scan = :ack_scan
      end

      opts.on("--sW", "--window-scan",
        "Window scan") do
        @options.window_scan = :window_scan
      end

      opts.on("--sM", "--maimon-scan",
        "Maimon scan") do
        @options.maimon_scan = :maimon_scan
      end

      opts.on("--scanflags ", String,
         "<flags>: Customize TCP scan flags") do |tcp_scan_flags|
        @options.tcp_scan_flags = tcp_scan_flags
      end

      opts.on("--sZ", "--sctp-cookie-scan",
        "SCTP INIT/COOKIE-ECHO Scans") do
        @options.sctp_cookie_echo_scan = :sctp_cookie_echo_scan
      end

      opts.on("--sI", "--idle-scan",
        "<zombie host[:probeport]>: Idle scan") do
        @options.idle_scan= :idle_scan
      end

      opts.on("--sO", "--ip-scan",
        "IP protocol scan") do
        @options.ip_scan = :ip_scan
      end

      opts.on("--b", "--ftp-bounce-scan ", String,
         "<FTP relay host>: FTP bounce scan") do |ftp_bounce_scan|
        @options.ftp_bounce_scan  = ftp_bounce_scan 
      end

      # Port Specification and Scan Order:

      opts.on("--p", "--ports ", String,
         "<port ranges>: Only scan specified ports") do |ports|
        @options.ports = ports 
      end

      opts.on("--F", "--fast",
        "Fast mode - Scan fewer ports than the default scan") do
        @options.fast = :fast
      end

      opts.on("--c", "--consecutively",
        "Scan ports consecutively - don't randomize") do
        @options.consecutively = :consecutively
      end

      opts.on("--top-ports ", String,
        "<number>: Scan <number> most common ports") do |top_ports|
        @options.top_ports = top_ports
      end

      opts.on("--port-ratio ", String,
        "<ratio>: Scan ports more common than <ratio>") do |port_ratio|
        @options.port_ratio = port_ratio
      end

      # Service/Version Detection:

      opts.on("--sV", "--service-scan",
        "Probe open ports to determine service/version info") do
        @options.service_scan = :service_scan
      end

      opts.on("--allports",
        "Don't exclude any ports from version detection") do
        @options.all_ports = :all_ports 
      end

      opts.on("--version-intensity ", String,
        "<level>: Set from 0 (light) to 9 (try all probes)") do |version_intensity|
        @options.version_intensity = version_intensity
      end

      opts.on("--version-light",
        "Limit to most likely probes (intensity 2)") do
        @options.version_light = :version_light
      end

      opts.on("--version-all",
        "Try every single probe (intensity 9)") do
        @options.version_all = :version_all
      end

      opts.on("--version-trace",
        "Show detailed version scan activity (for debugging)") do
        @options.version_trace = :version_trace
      end

      opts.on("--sR", "--rpc-scan",
        "RPC scan") do
        @options.rpc_scan = :rpc_scan
      end

      # Script Scan:

      opts.on("--sC", "--default-script",
        "Equivalent to --script=default") do
        @options.default_script = :default_script
      end

      opts.on("--script ", String,
         "Pass a script") do |script|
        @options.script = script 
      end

      opts.on("--script-args ", String,
         "filename: provide NSE script args in a file") do |script_params|
        @options.script_params = script_params 
      end

      opts.on("--script-trace",
        "Show all data sent and received") do
        @options.script_trace = :script_trace
      end

      opts.on("--script-updatedb",
        "Update the script database.") do
        @options.update_scriptdb = :update_scriptdb
      end

      # OS Detection:

      opts.on("--O", "--os-fingerprint",
        "Enable OS detection") do
        @options.os_fingerprint = :os_fingerprint
      end

      opts.on("--osscan-limit",
        "Limit OS detection to promising targets") do
        @options.limit_os_scan = :limit_os_scan
      end

      opts.on("--osscan-guess",
        "Guess OS more aggressively") do
        @options.max_os_scan = :max_os_scan
      end

      # Timing and Performance:
      
      opts.on("--min-hostgroup ", String,
         "<size>: Parallel host scan group sizes") do |min_host_group|
        @options.min_host_group = min_host_group
      end

      opts.on("--max-hostgroup ", String,
         "<size>: Parallel host scan group sizes") do |max_host_group|
        @options.max_host_group = max_host_group
      end

      opts.on("--min-parallelism ", String,
         "<numprobes>: Probe parallelization") do |min_parallelism|
        @options.min_parallelism = min_parallelism
      end

      opts.on("--max-parallelism ", String,
         "<numprobes>: Probe parallelization") do |max_parallelism|
        @options.max_parallelism = max_parallelism
      end

      opts.on("--min-rtt-timeout ", String,
         "<time>: Specifies") do |min_rtt_timeout|
        @options.min_rtt_timeout = min_rtt_timeout
      end

      opts.on("--max-rtt-timeout ", String,
         "<time>: Specifies") do |max_rtt_timeout|
        @options.max_rtt_timeout = max_rtt_timeout
      end

      opts.on("--max-retries ", String,
         "<tries>: Caps number of port scan probe retransmissions.") do |max_retries|
        @options.max_retries = max_retries
      end

      opts.on("--host-timeout ", String,
         "<time>: Give up on target after this long") do |host_timeout|
        @options.host_timeout = host_timeout
      end

      opts.on("--scan-delay ", String,
         "<time>: Adjust delay between probes") do |scan_delay|
        @options.scan_delay = scan_delay
      end

      opts.on("--max-scan-delay ", String,
         "<time>: Adjust delay between probes") do |max_scan_delay|
        @options.max_scan_delay = max_scan_delay
      end

      opts.on("--min-rate ", String,
         "<number>: Send packets no slower than <number> per second") do |min_rate|
        @options.min_rate = min_rate
      end

      opts.on("--max-rate ", String,
         "<number>: Send packets no faster than <number> per second") do |max_rate|
        @options.max_rate = max_rate
      end

      opts.on("--defeat-rst-ratelimit ", String,
         "Defeat targets that apply rate limiting") do |defeat_rst_ratelimit|
        @options.defeat_rst_ratelimit = defeat_rst_ratelimit
      end

      opts.on("--defeat-icmp-ratelimit ", String,
         "Increasing UDP scanning speed against hosts that rate-limit ICMP error messages") do |defeat_icmp_ratelimit|
        @options.defeat_icmp_ratelimit = defeat_icmp_ratelimit
      end

      opts.on("--nsock-engine ", String,
         "Enforce use of a given nsock IO multiplexing engine") do |nsock_engine|
        @options.nsock_engine = nsock_engine
      end

      opts.on("--T","--timing-template ", String,
         "<0-5>: Set timing template (higher is faster)") do |timing_template|
        @options.timing_template = timing_template
      end

      opts.on("--T0","--paranoid-timing",
        "Paranoid timing") do
        @options.paranoid_timing = :paranoid_timing 
      end

      opts.on("--T1","--sneaky-timing",
        "Sneaky timing") do
        @options.sneaky_timing = :sneaky_timing
      end

      opts.on("--T2","--polite-timing",
        "Polite timing") do
        @options.polite_timing = :polite_timing
      end

      opts.on("--T3","--normal-timing",
        "Normal timing") do
        @options.normal_timing = :normal_timing
      end

      opts.on("--T4","--aggressive-timing",
        "Aggresive timing") do
        @options.aggressive_timing = :aggressive_timing
      end

      opts.on("--T5","--insane-timing",
        "Insane timing") do
        @options.insane_timing = :insane_timing
      end

      # Firewall/IDS Evasion and Spoofing:

      opts.on("--packet-fragments",
        "<val>: fragment packets (optionally w/given MTU)") do
        @options.packet_fragments = :packet_fragments 
      end

      opts.on("--mtu ", String,
       "<val>: fragment packets (optionally w/given MTU)") do |mtu|
        @options.mtu = mtu
      end

      opts.on("--decoys ", String,
        "Cloak a scan with decoys") do |decoys|
        @options.decoys = decoys 
      end

      opts.on("--S", "--spoof ", String,
        "<IP_Address>: Spoof source address") do |spoof|
        @options.spoof = spoof 
      end

      opts.on("--e", "--interface ", String,
        "<iface>: Use specified interface") do |interface|
        @options.interface = interface
      end

      opts.on("--g", "--source-port ", String,
        "<portnum>: Use given port number") do |source_port|
        @options.source_port = source_port
      end

      opts.on("--data-length ", String,
        "<num>: Append random data to sent packets") do |data_length|
        @options.data_length = data_length 
      end

      opts.on("--ip-options ", String,
        "<options>: Send packets with specified ip options") do |ip_options|
        @options.ip_options = ip_options
      end

      opts.on("--ttl ", String,
        "<val>: Set IP time-to-live field") do |ttl|
        @options.ttl = ttl 
      end

     opts.on("--randomize-hosts",
        "Randomize target host order") do
        @options.randomize_hosts = :randomize_hosts
      end

      opts.on("--spoof-mac ", String,
        "<mac address/prefix/vendor name>: Spoof your MAC address") do |spoof_mac|
        @options.spoof_mac = spoof_mac 
      end

     opts.on("--badsum",
        "Send packets with a bogus TCP/UDP/SCTP checksum") do
        @options.bad_checksum = :bad_checksum 
      end

      opts.on("--adler32",
        "Use deprecated Adler32 instead of CRC32C for SCTP checksums") do
        @options.sctp_adler32 = :sctp_adler32 
      end

      # Output:

      opts.on("--oN","--save ", String,
        "<file>: Output scan in normal format") do |save|
        @options.save = save
      end

      opts.on("--oX","--xml ", String,
        "<file>: Output scan in XML format") do |xml|
        @options.xml = xml 
      end

      opts.on("--oS","--skiddie ", String,
       "<file>: Output scan in s|<rIpt kIddi3 format") do |skiddie|
        @options.skiddie = skiddie
      end

      opts.on("--oG","--grep ", String,
        "<file>: Output scan in grepable format") do |grep|
        @options.grep = grep
      end

      opts.on("--oA","--output-all ", String,
        "<basename>: Output in the three major formats at once") do |output_all|
        @options.output_all = output_all
      end

      # Verbosity and Debugging:

      opts.on("--v","--verbose",
        "Increase verbosity level") do
        @options.verbose = :verbose
      end

      opts.on("--q","--quiet",
        "Set verbosity and debug level to minimum") do
        @options.quiet = :quiet
      end

      opts.on("--d", "--debug",
        "Increase debugging level") do
        @options.debug = :debug
      end

      opts.on("--reason",
        "Display the reason a port is in a particular state") do
        @options.show_reason = :show_reason
      end

      opts.on("--stats-every ", String,
        "Print periodic timing stats") do |stats_every|
        @options.stats_every = stats_every
      end

      opts.on("--packet-trace",
        "Show all packets sent and received") do
        @options.show_packet = :show_packet
      end

      opts.on("--open",
        "Only show open (or possibly open) ports") do
        @options.show_open_ports = :show_open_ports
      end

      opts.on("--iflist",
        "Print host interfaces and routes (for debugging)") do
        @options.show_interfaces = :show_interfaces
      end

      opts.on("--log-errors",
        "Log errors/warnings to the normal-format output file") do
        @options.show_log_errors = :show_log_errors
      end

      # Miscellaneous Output:

      opts.on("--append-output",
        "Append to rather than clobber output files") do
        @options.append = :append
      end

      opts.on("--resume ", String,
        "<filename>: Resume an aborted scan") do |resume|
        @options.resume = resume
      end

      opts.on("--stylesheet ", String,
        "<path/URL>: XSL stylesheet to transform XML output to HTML") do |stylesheet|
        @options.stylesheet = stylesheet
      end

      opts.on("--webxml",
        "Load stylesheet from Nmap.Org") do
        @options.nmap_stylesheet = :nmap_stylesheet
      end

      opts.on("--no-stylesheet",
        "Prevent associating of XSL stylesheet w/XML output") do
        @options.disable_stylesheet = :disable_stylesheet
      end

      # Misc:

      opts.on("--6", "--ipv6",
        "Enable IPv6 scanning") do
        @options.ipv6 = :ipv6
      end

      opts.on("--A", "--all",
        "Enable OS detection, version detection, script scanning, and traceroute") do
        @options.all = :all
      end

      opts.on("--datadir ", String,
        "Specify custom Nmap data file location") do |nmap_datadir|
        @options.nmap_datadir = nmap_datadir
      end

      opts.on("--servicedb ", String,
        "Specify custom services file") do |servicedb|
        @options.servicedb = servicedb 
      end

      opts.on("--versiondb ", String,
        "Specify custom service probes file") do |versiondb|
        @options.versiondb = versiondb  
      end

      opts.on("--send-eth",
        "Use raw ethernet sending") do
        @options.raw_ethernet = :raw_ethernet
      end

      opts.on("--send-ip",
        "Send at raw IP level") do
        @options.raw_ip = :raw_ip
      end

      opts.on("--privileged",
        "Assume that the user is fully privileged") do
        @options.privileged = :privileged
      end

      opts.on("--release-memory",
        "Release memory before quitting") do
        @options.release_memory = :release_memory
      end

      opts.on("--target ", String,
        "{target specification}") do |targets|
        @options.targets = targets 
      end

      opts.on("--version",
        "Print version number") do
        puts Version
        exit
      end

      opts.on("--h","--help", 
        "Print this help summary page.") do
        puts opts
        exit   
      end

    begin
      opts.parse!(args)

    rescue OptionParser::ParseError => error
      puts "[!]".red + error.message.bold
      puts opts
      exit
    end
  end
end

def port_scan

  Nmap::Program.scan do |nmap|

  # Host Discovery:

  if @options.list == :list then
    nmap.list = true
  end

  if @options.ping == :ping then
    nmap.ping = true
  end

  if @options.skip_discovery == :skip_discovery then
    nmap.skip_discovery = true
  end

  nmap.syn_discovery = @options.syn_discovery
  nmap.ack_discovery = @options.ack_discovery
  nmap.udp_discovery = @options.udp_discovery
  nmap.sctp_init_ping = @options.sctp_init_ping

  if @options.icmp_echo_discovery == :icmp_echo_discovery then
    nmap.icmp_echo_discovery = true
  end

  if @options.icmp_timestamp_discovery == :icmp_timestamp_discovery then
    nmap.icmp_timestamp_discovery = true
  end

  if @options.icmp_netmask_discovery == :icmp_netmask_discovery then
    nmap.icmp_netmask_discovery = true
  end

  if @options.ip_ping == :ip_ping then
    nmap.ip_ping = true
  end

  if @options.arp_ping == :arp_ping then
    nmap.arp_ping = true
  end

  if @options.traceroute == :traceroute then
    nmap.traceroute = true
  end

  if @options.disable_dns == :disable_dns then
    nmap.disable_dns = true
  end

  if @options.enable_dns == :enable_dns then
    nmap.enable_dns = true
  end

  if @options.system_dns == :system_dns then
    nmap.system_dns = true
  end

  nmap.dns_servers = @options.dns_servers

  # Port Scanning Techniques:

  if @options.syn_scan == :syn_scan then
    nmap.syn_scan = true
  end

  if @options.connect_scan == :connect_scan then
    nmap.connect_scan = true
  end

  if @options.udp_scan == :udp_scan then
    nmap.udp_scan = true
  end

  if @options.sctp_init_scan == :sctp_init_scan then
    nmap.sctp_init_scan = true
  end

  if @options.null_scan == :null_scan then
    nmap.null_scan = true
  end

  if @options.fin_scan == :fin_scan then
    nmap.fin_scan = true
  end

  if @options.xmas_scan == :xmas_scan then
    nmap.xmas_scan = true
  end

  if @options.ack_scan == :ack_scan then
    nmap.ack_scan = true
  end

  if @options.window_scan == :window_scan then
    nmap.window_scan = true
  end

  if @options.maimon_scan == :maimon_scan then
    nmap.maimon_scan = true
  end

  nmap.tcp_scan_flags = @options.tcp_scan_flags

  if @options.sctp_cookie_echo_scan == :sctp_cookie_echo_scan then
    nmap.sctp_cookie_echo_scan = true
  end

  if @options.idle_scan == :idle_scan then
    nmap.idle_scan = true
  end

  if @options.ip_scan == :ip_scan then
    nmap.ip_scan = true
  end

  nmap.ftp_bounce_scan = @options.ftp_bounce_scan 

  # Port Specification and Scan Order:

  nmap.ports = @options.ports

  if @options.fast == :fast then
    nmap.fast = true
  end

  if @options.consecutively == :consecutively then
    nmap.consecutively = true
  end

  nmap.top_ports = @options.top_ports
  nmap.port_ratio = @options.port_ratio

  # Service/Version Detection:

  if @options.service_scan == :service_scan then
    nmap.service_scan = true
  end

  if @options.all_ports == :all_ports then
    nmap.all_ports = true
  end

  nmap.version_intensity = @options.version_intensity

  if @options.version_light == :version_light then
    nmap.version_light = true
  end

  if @options.version_all == :version_all then
    nmap.version_all = true
  end

  if @options.version_trace == :version_trace then
    nmap.version_trace = true
  end

  if @options.rpc_scan == :rpc_scan then
    nmap.rpc_scan = true
  end

  # Script Scan:

  if @options.default_script == :default_script then
    nmap.default_script = true
  end

  nmap.script = @options.script
  nmap.script_params = @options.script_params

  if @options.script_trace == :script_trace then
    nmap.script_trace = true
  end

  if @options.update_scriptdb == :update_scriptdb then
    nmap.update_scriptdb = true
  end

  # OS Detection:

  if @options.os_fingerprint == :os_fingerprint then
    nmap.os_fingerprint = true
  end 

  if @options.limit_os_scan == :limit_os_scan then
    nmap.limit_os_scan = true
  end 

  if @options.max_os_scan == :max_os_scan then
    nmap.max_os_scan = true
  end 

  # Timing and Performance:
  
  nmap.min_host_group = @options.min_host_group
  nmap.max_host_group = @options.max_host_group
  nmap.min_parallelism = @options.min_parallelism
  nmap.max_parallelism = @options.max_parallelism
  nmap.min_rtt_timeout = @options.min_rtt_timeout
  nmap.max_rtt_timeout = @options.max_rtt_timeout
  nmap.max_retries = @options.max_retries
  nmap.host_timeout = @options.host_timeout
  nmap.scan_delay = @options.scan_delay
  nmap.max_scan_delay = @options.max_scan_delay
  nmap.min_rate = @options.min_rate
  nmap.max_rate = @options.max_rate
  nmap.defeat_rst_ratelimit = @options.defeat_rst_ratelimit 
  nmap.defeat_icmp_ratelimit = @options.defeat_icmp_ratelimit
  nmap.nsock_engine = @options.nsock_engine
  nmap.timing_template = @options.timing_template

  if @options.paranoid_timing == :paranoid_timing then
    nmap.paranoid_timing = true
  end 

  if @options.sneaky_timing == :sneaky_timing then
    nmap.sneaky_timing = true
  end
 
  if @options.polite_timing == :polite_timing then
    nmap.polite_timing = true
  end

  if @options.normal_timing == :normal_timing then
    nmap.normal_timing = true
  end

  if @options.aggressive_timing == :aggressive_timing then
    nmap.aggressive_timing = true
  end

  if @options.insane_timing == :insane_timing then
    nmap.insane_timing = true
  end

  # Firewall/IDS Evasion and Spoofing:

  if @options.packet_fragments == :packet_fragments then
    nmap.packet_fragments = true
  end 

  nmap.mtu = @options.mtu
  nmap.decoys = @options.decoys
  nmap.spoof = @options.spoof
  nmap.interface = @options.interface
  nmap.source_port = @options.source_port
  nmap.data_length  = @options.data_length
  nmap.ip_options = @options.ip_options
  nmap.ttl = @options.ttl

  if @options.randomize_hosts == :randomize_hosts then
    nmap.randomize_hosts = true
  end 

  nmap.spoof_mac = @options.spoof_mac

  if @options.bad_checksum == :bad_checksum then
    nmap.bad_checksum = true
  end

  if @options.sctp_adler32 == :sctp_adler32 then
    nmap.sctp_adler32 = true
  end

  # Output:

  nmap.save = @options.save
  nmap.xml = @options.xml
  nmap.skiddie = @options.skiddie
  nmap.grepable = @options.grep
  nmap.output_all = @options.output_all

  # Verbosity and Debugging:

  if @options.verbose == :verbose then 
    nmap.verbose = true
  end

  if @options.quiet == :quiet then 
    nmap.quiet = true
  end

  if @options.debug == :debug then
    nmap.debug = true
  end

  if @options.show_reason == :show_reason then
    nmap.show_reason = true
  end

  nmap.stats_every = @options.stats_every

  if @options.show_packet == :show_packet then
    nmap.show_packets = true
  end

  if @options.show_open_ports == :show_open_ports then
    nmap.show_open_ports = true
  end

  if @options.show_interfaces == :show_interfaces then
    nmap.show_interfaces = true
  end

  if @options.show_log_errors == :show_log_errors then
    nmap.show_log_errors = true
  end

  # Miscellaneous Output:

  if @options.append == :append then
    nmap.append = true
  end

  nmap.resume = @options.resume
  nmap.stylesheet = @options.stylesheet

  if @options.nmap_stylesheet == :nmap_stylesheet then
    nmap.nmap_stylesheet = true
  end

  if @options.disable_stylesheet == :disable_stylesheet then
    nmap.disable_stylesheet = true
  end

  # Misc:

  if @options.ipv6 == :ipv6  then
    nmap.ipv6  = true
  end

  if @options.all == :all then
    nmap.all = true
  end

  nmap.nmap_datadir = @options.nmap_datadir
  nmap.servicedb = @options.servicedb
  nmap.versiondb = @options.versiondb

  if @options.raw_ethernet == :raw_ethernet then
    nmap.raw_ethernet = true
  end

  if @options.raw_ip == :raw_ip then
    nmap.raw_ip = true
  end

  if @options.privileged == :privileged then
    nmap.privileged = true
  end

  if @options.release_memory == :release_memory then
    nmap.release_memory = true
  end

  nmap.targets = @options.targets

  end
end

  def run(args)
    parse_opts(args)
    port_scan
  end
end

nmap = Rnmap.new
nmap.run(ARGV)
