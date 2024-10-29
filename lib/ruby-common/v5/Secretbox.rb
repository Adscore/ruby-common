require 'rbnacl'

class Secretbox < AbstractSymmetricCrypt
  METHOD = 0x0101

  def decrypt_with_key(payload, key)
    nonce_bytes = 24
    parse = parse(payload, { iv: nonce_bytes })
    secret_box = RbNaCl::SecretBox.new(key)
    return secret_box.decrypt(parse.byte_buffer_map[:iv], parse.data)
  rescue RbNaCl::CryptoError
    raise 'Decryption failed'
  end
end