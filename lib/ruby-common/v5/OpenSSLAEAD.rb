require_relative "./AbstractSymmetricCrypt.rb"

class OpenSSLAEAD < AbstractSymmetricCrypt
  METHOD = 0x0201

  def initialize(tag: 16, crypt_method: "AES-256-GCM")
    @tag= tag
    @crypt_method = crypt_method
    @crypt_iv = CryptMethodConstans::CRYPT_METHODS[crypt_method]
  end

  def decrypt_with_key(payload, key)
    lengths = {"iv" => @crypt_iv, "tag" => @tag}
    result = parse(payload, lengths)

    raise DecryptError, 'Unrecognized payload' if result.method != METHOD;

    return decode(
      result.data,
      key,
      result.byte_buffer_map['iv'],
      result.byte_buffer_map['tag']
    )
  end

  private
  def decode(input, key, iv, tag)
    cipher = OpenSSL::Cipher.new(@crypt_method)
    cipher.decrypt

    cipher.key = key.bytes.pack('C*')
    cipher.iv = iv.bytes.pack('C*')
    cipher.auth_tag = tag.bytes.pack('C*')

    return cipher.update(input) + cipher.final
  rescue OpenSSL::Cipher::CipherError => e
    raise DecryptError.new("Decryption failed: #{e.message}")
  end


end