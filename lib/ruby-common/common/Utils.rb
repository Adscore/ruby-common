# Utility class for signature verification
class SignatureVerifierUtils
  def self.character_to_int(value)
    value.to_i
  end

  def self.base64_decode(key)
    if key.include? "-" or key.include? "_" then
      return Base64.urlsafe_decode64(key)
    end
    return Base64.decode64(key)
  end

  def self.encode(key, data)
    begin
      hmac = OpenSSL::HMAC.new(key, 'sha256')
      return hmac.update(data).digest
    rescue StandardError => e
      raise SignatureParseError, "Error encode data"
    end
  end
end