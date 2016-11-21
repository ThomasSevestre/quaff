# -*- coding: us-ascii -*-
require 'milenage'

module Quaff

class AKARegistrationControl
  attr_reader :res

  def initialize username, uri, password, opaque, sqn, amf
    @username = username
    @number, @domain = @username.split('@')
    @uri = uri
    @cnonce = SecureRandom.hex(4)
    @cnonce_count = 1

    @password = password
    @kernel = Milenage::Kernel.new(@password)
    @kernel.op = opaque
    @rsqn = sqn
    @amf = amf
  end

  def calc_aka hdr
    rand = Quaff::Auth.extract_rand hdr
    autn = Quaff::Auth.extract_autn hdr
    ak = @kernel.f5 rand
    mac = @kernel.f1 rand, @rsqn.to_s, @amf.to_s
    ck = @kernel.f3 rand
    cks = ck.unpack("H*").join
    ik = @kernel.f4 rand
    iks = ik.unpack("H*").join
    res = @kernel.f2 rand
    return res, iks, cks
  end

  def gen_auth_hdr_rsp method, response_data
    rcv_auth_hdr = response_data.header("WWW-Authenticate")
    @res,ik,ck = calc_aka rcv_auth_hdr
    @auth_hdr_rsp = Auth.gen_auth_header rcv_auth_hdr, @username, @res, method, @uri
  end

end

end
