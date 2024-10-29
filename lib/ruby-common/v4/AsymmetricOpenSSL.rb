require 'openssl'
require 'base64'

module AsymmetricOpenSSL

  def self.verify_data(data, token, public_key_pem)
    pub_key = OpenSSL::PKey::EC.new(public_key_pem)
    digest = OpenSSL::Digest.new('sha256')
    pub_key.verify(digest,token, data)
  end
end