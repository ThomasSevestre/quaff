# -*- coding: us-ascii -*-
require 'milenage'

module Quaff

class AKARegistrationControl

  def initialize username, uri, password, opaque, sqn, amf
    @username = username
    @number, @domain = @username.split('@')
    @uri = uri
    gen_cnonce

    @password = password
    @kernel = Milenage::Kernel.new(@password)
    @kernel.op = opaque
    @rsqn = sqn
    @amf = amf
  end

  def gen_cnonce
    @cnonce = SecureRandom.hex(4)
    @cnonce_count = 1
  end
    
  def inc_cnonce_cnt
    @cnonce_count += 1
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

  def gen_credentials response_data
    rcv_auth_hdr = response_data.header("WWW-Authenticate")
    @res,ik,ck = calc_aka rcv_auth_hdr
  end

  def gen_auth_hdr
      auth_hdr = Quaff::Auth.gen_initial_aka_auth_header @username, @domain, @uri
  end

  def gen_digest_auth_hdr_rsp method, response_data, bad_pass=false
    rcv_auth_hdr = response_data.header("WWW-Authenticate")
    nc = sprintf("%08d", @cnonce_count)
    @last_response_data = response_data
    if bad_pass
      password = "xxxxxxxx"
    else
      password = @password
    end
    @auth_hdr_rsp = Auth.gen_digest_resp_auth_header rcv_auth_hdr, @username, password, method, @uri, nc, @cnonce
  end

# the password is not used in AKA authentication so a bad password at this point
# doesn't mean anything.  The password is used in the security association establishment
  def gen_auth_hdr_rsp method, response_data, bad_pass=false, nonce_count=nil
    rcv_auth_hdr = response_data.header("WWW-Authenticate")
    if !nonce_count.nil?
      nc = sprintf("%08d", nonce_count)
    else
      nc = sprintf("%08d", @cnonce_count)
    end
    @last_response_data = response_data
    if bad_pass
      res = "xxxxxxxxxxxxxxxx"
    else
      res = @res
    end
    @auth_hdr_rsp = Auth.gen_aka_resp_auth_header rcv_auth_hdr, @username, @password, method, @uri, nc, @cnonce, res
  end

  def gen_auth_hdr_req method
    rcv_auth_hdr = @last_response_data.header("WWW-Authenticate")
#    @cnonce_count += 1
    gen_cnonce
    nc = sprintf("%08d", @cnonce_count)
    auth_hdr = Auth.gen_aka_resp_auth_header rcv_auth_hdr, @username, @password, method, @uri, nc, @cnonce, @res
  end

  def auth_hdr_rsp
    @auth_hdr_rsp
  end

end

end
