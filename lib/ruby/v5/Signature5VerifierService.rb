require 'base64'
require 'date'

require_relative '../common/PhpUnpack.rb'
require_relative '../common/Ipv6Utils.rb'
require_relative '../common/Utils.rb'
require_relative '../common/Exceptions.rb'
require_relative './CryptMethodConstans.rb'
require_relative './AbstractSymmetricCrypt.rb'
require_relative './MyOpenSSL.rb'
require_relative './OpenSSLAEAD.rb'
require_relative './Secretbox.rb'
require_relative './StructUnpacker.rb'
require_relative './Secretbox.rb'
require_relative '../common/VerifierConstants.rb'
require_relative './Signature5VerificationResult.rb'
require_relative './CryptFactory.rb'


class Signature5VerifierService
  VERSION = 5;
  HEADER_LENGTH = 11;

  def self.verifySignature(signature, user_agent, key, ip_addresses)
    parsed = parse(signature, key)
    verify(parsed, ip_addresses, user_agent)
    return Signature5VerificationResult.new(parsed)
  end

  class << self
    private


    def parse(signature, key)
      signature_decoded = SignatureVerifierUtils.base64_decode(signature)
      key = SignatureVerifierUtils.base64_decode(key)

      raise SignatureParseError, 'Malformed signature' if signature_decoded.bytes.length < HEADER_LENGTH;

      unpack = PhpUnpack.unpack("Cversion/nlength/Jzone_id", signature_decoded);

      raise SignatureParseError, 'Malformed signature' if unpack['version'].first != VERSION;

      length = unpack['length'].first;
      zone_id = unpack['zone_id'];

      raise SignatureParseError, 'Truncated signature payload' if signature_decoded.bytes.length < length;

      decrypted_payload = decrypt_payload(signature_decoded, key)
      decrypted_payload['zone_id']= zone_id
      return decrypted_payload
    end

    def decrypt_payload(signature_decoded, key)
      crypt = CryptFactory.create_from_payload(signature_decoded)
      decrypted_payload = crypt.decrypt_with_key(signature_decoded, key)
      return StructUnpacker::parse_payload(decrypted_payload)
    end

    def verify(parsed, ip_addresses, user_agent)
      matching_ip = nil
    
      ip_addresses.each do |ip_address|
        if parsed['ipv4.ip']
          if ip_address == parsed['ipv4.ip']
            matching_ip = ip_address
            break
          end
        end
    
        if parsed['ipv6.ip']
          if IpV6Utils.abbreviate(parsed['ipv6.ip']) == IpV6Utils.abbreviate(ip_address)
            matching_ip = ip_address
            break
          end
        end
      end
    
      raise VerifyError, 'Signature IP mismatch' if matching_ip.nil?
      unless parsed['b.ua'] == user_agent
        raise VerifyError, 'Signature user agent mismatch'
      end

      unless VerifierConstants::RESULTS[parsed['result'].to_i] == parsed['verdict']
        raise VerifyError, 'Result mismatch'
      end
    end

  end
end
