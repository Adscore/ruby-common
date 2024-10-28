require_relative "./AbstractSymmetricCrypt.rb"
require_relative "./CryptMethodConstans.rb"


class MyOpenSSL < AbstractSymmetricCrypt
  METHOD = 0x0200

  def initialize(crypt_method: "AES-256-CBC")
    if CryptMethodConstans::CRYPT_METHODS.key?(crypt_method)
      @crypt_method = crypt_method
      @crypt_iv = CryptMethodConstans::CRYPT_METHODS[crypt_method]
    else
      raise DecryptError, "Method not supported #{crypt_method}"
    end
  end

  def decrypt_with_key(payload, key)
    lengths = {"iv" => @crypt_iv}
    result = parse(payload, lengths)

    raise DecryptError, 'Unrecognized payload' if result.method != METHOD;

    return decode(payload, key, result.byte_buffer_map['iv'])
  end

  def decode(input, key, iv)
    begin
      cipher = OpenSSL::Cipher.new(@crypt_method)
      cipher.decrypt

      cipher.key = key.bytes.pack('C*')
      cipher.iv = iv.bytes.pack('C*')

      return cipher.update(input) + cipher.final
    rescue StandardError => e
      raise DecryptError, "Decryption OpenSSL failed: #{e.message}"
    end
  end
end