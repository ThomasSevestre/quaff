require 'resolv'
require 'socket'
require 'system/getifaddrs'

module Quaff

module Utils #:nodoc:
def Utils.local_ip
  addrs = System.get_ifaddrs
  if addrs.empty?
    "0.0.0.0"
  elsif (addrs.size == 1)
    addrs[0][:inet_addr]
  else
    addrs.select {|k, v| k != :lo}.shift[1][:inet_addr]
  end
end

def Utils.pid
    Process.pid
end

def Utils.new_call_id
    "#{pid}_#{Time.new.to_i}@#{local_ipv4}"
end

def Utils.new_branch
    "z9hG4bK#{Time.new.to_f}"
end

def Utils.paramhash_to_str params
  params.collect {|k, v| if (v == true) then ";#{k}" else ";#{k}=#{v}" end}.join("")
end

def Utils.check_route_matches_destination route, destination
  # Get the address and port out of the destination (note that destination.ip can be a hostname).
  dest_address = destination.ip
  dest_port = destination.port
  regexp = /<sip:(?:.*?@)?(.*?):(.*?);.*?>/i
  if route =~ regexp
    route_address = $1
    route_port = $2
  end

  # Get IPs from hostnames.
  route_ips = Resolv.getaddresses(route_address)
  dest_ips = Resolv.getaddresses(dest_address)

  # Check that there is at least one address common between the route and the destination,
  # and that the ports are the same.
  if (route_ips & dest_ips).empty?
    raise "Error: Address in top route header '#{route_address}' does not match destination address '#{dest_address}'"
  elsif (route_port.to_s != dest_port.to_s)
    raise "Error: Port in top route header '#{route_port}' does not match destination port '#{dest_port}'"
  end
end

end
end
