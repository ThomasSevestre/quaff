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
  regexp = /<sip:(.*?)@(.*?):(.*?);(.*?)>/i
  dest_address = destination.instance_variable_get(:@ip)
  dest_port = destination.instance_variable_get(:@port)
  if route =~ regexp
    route_address = $2
    route_port = $3
  end

  route_ip = []
  Resolv.each_address(route_address) do |address|
    route_ip << address
  end

  dest_ip = []
  Resolv.each_address(dest_address) do |address|
    dest_ip << address
  end

  if (route_ip & dest_ip).empty?
    raise "Error: Address in top route header '#{route_address}' does not match destination address '#{dest_address}'"
  elsif (route_port.to_s != dest_port.to_s)
    raise "Error: Port in top route header '#{route_port}' does not match destination port '#{dest_port}'"
  end
end

end
end
