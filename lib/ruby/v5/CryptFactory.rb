class CryptFactory
  def self.create_from_payload(payload)
    header = payload.byteslice(0,2)
    return create_crypt(header)
  end

  private
  def self.create_crypt(name)
    case name.unpack("v").first
    when MyOpenSSL::METHOD
      MyOpenSSL.new
    when OpenSSLAEAD::METHOD
      OpenSSLAEAD.new
    when Secretbox::METHOD
      Secretbox.new
    else
      raise SignatureParseError, "Unsupported crypt class"
    end
  end
end