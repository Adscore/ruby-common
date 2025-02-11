require 'base64'
require 'date'
require 'openssl'
require 'securerandom'

require_relative '../common/PhpUnpack.rb'
require_relative '../common/Ipv6Utils.rb'
require_relative './AsymmetricOpenSSL.rb'
require_relative '../common/Utils.rb'
require_relative '../common/Exceptions'
require_relative '../common/VerifierConstants.rb'
require_relative './Signature4VerificationResult.rb'


# Helper class to represent field information
class Field
attr_reader :name, :type

  def initialize(name, type)
    @name = name
    @type = type
  end
end

# Signature4VerifierService class
class Signature4VerifierService
  FIELD_IDS = {
    0x00 => Field.new('requestTime', 'ulong'),
    0x01 => Field.new('signatureTime', 'ulong'),
    0x10 => Field.new('ipv4', 'ulong'),
    0x40 => Field.new(nil, 'ushort'),
    0x80 => Field.new('masterSignType', 'uchar'),
    0x81 => Field.new('customerSignType', 'uchar'),
    0xC0 => Field.new('masterToken', 'string'),
    0xC1 => Field.new('customerToken', 'string'),
    0xC2 => Field.new('masterTokenV6', 'string'),
    0xC3 => Field.new('customerTokenV6', 'string'),
    0xc4 => Field.new('ipv6', 'string'),
    0xc5 => Field.new('masterChecksum', 'string'),
    0xd0 => Field.new('userAgent', 'string') #DEBUG FIELD
  }.freeze

  def self.verifySignature(signature, user_agent, key, ip_addresses, expiry, is_key_base64_encoded)
    validation_result = {}

    begin
      data = parse4(signature)
    rescue VersionError
      data = parse3(signature)
    end

    sign_role_token = data["customerToken"]

    if sign_role_token.nil? || sign_role_token.empty?
      raise VerifyError, 'sign role signature mismatch'
    end

    sign_type = data["customerSignType"]

    ip_addresses.each do |ip_address|
      next if ip_address.nil? || ip_address.empty?

      token = if IpV6Utils.validate(ip_address)
                next unless data.key?("customerTokenV6")
                IpV6Utils.abbreviate(ip_address)
                data["customerTokenV6"]
              else
                next unless data.key?("customerToken")
                data["customerToken"]
              end

      signature_time = data['signatureTime'].first
      request_time = data['requestTime'].first

      VerifierConstants::RESULTS.each do |result, verdict|
        signature_base = get_base(result, request_time, signature_time, ip_address, user_agent)

        case sign_type.first
        when 1 # HASH_SHA256
          is_hashed_data_equal_to_token = SignatureVerifierUtils.encode(
            is_key_base64_encoded ? SignatureVerifierUtils.base64_decode(key) : key,
            signature_base
          ) == token
          
          if is_hashed_data_equal_to_token
            if is_expired(expiry, signature_time, request_time)
              return Signature4VerificationResult.is_expired
            end

            return Signature4VerificationResult.new(
              score: result.to_i,
              verdict: verdict,
              ip_address: ip_address,
              request_time: request_time,
              signature_time: signature_time
            )
          end
        when 2 # SIGN_SHA256
          if AsymmetricOpenSSL.verify_data(signature_base, token, key)
            return Signature4VerificationResult.new(
              score: result.to_i,
              verdict: verdict,
              ip_address: ip_address,
              request_time: request_time,
              signature_time: signature_time
            )
          end
        else
          raise VerifyError, 'unrecognized signature'
        end
      end
    end
    raise StructParseError, 'no verdict'
  end

  class << self
    private

    def parse3(signature)
      sign_decoded = SignatureVerifierUtils.base64_decode(signature)
      unpack_result = PhpUnpack.unpack('Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength', sign_decoded)

      version = unpack_result['version']
      raise VersionError, 'Invalid signature version' if version != 3

      timestamp = unpack_result['timestamp']
      raise SignatureParseError, 'invalid timestamp (future time)' if timestamp > (Time.now.to_i)

      master_token_length = unpack_result['masterTokenLength']
      master_token = sign_decoded.slice!(0, master_token_length)
      unpack_result['masterToken'] = master_token

      customer_data = PhpUnpack.unpack('CcustomerSignType/ncustomerTokenLength', sign_buffer)
      customer_token_length = customer_data['customerTokenLength']
      customer_token = sign_decoded.slice!(0, customer_token_length)
      customer_data['customerToken'] = customer_token

      unpack_result.merge!(customer_data)
    end

    def parse4(signature)
      sign_decoded = SignatureVerifierUtils.base64_decode(signature)
      raise SignatureParseError, 'invalid base64 payload' if sign_decoded.empty?

      data = PhpUnpack.unpack('Cversion/CfieldNum', sign_decoded)

      version = data['version'].first
      raise VersionError, 'Invalid signature version' if version != 4

      field_num = data['fieldNum'].first
      field_num.times do |i|
        header = PhpUnpack.unpack('CfieldId', sign_decoded)

        raise SignatureParseError, 'premature end of signature 0x01' if header.empty? || !header.key?('fieldId')

        field = field_type_def(header['fieldId'].first, i)
        v = {}

        case field&.type
        when 'uchar'
          v = PhpUnpack.unpack('Cv', sign_decoded)
          data[field.name] = v['v'] if v.key?('v')
        when 'ushort'
          v = PhpUnpack.unpack('nv', sign_decoded)
          data[field.name] = v['v'] if v.key?('v')
        when 'ulong'
          v = PhpUnpack.unpack('Nv', sign_decoded)
          data[field.name] = v['v'] if v.key?('v')
        when 'string'
          l = PhpUnpack.unpack('nl', sign_decoded)
          raise SignatureParseError, 'premature end of signature 0x05' unless l.key?('l')

          l_length = l['l'].first
          new_v = sign_decoded.slice!(0, l_length)
          v['v'] = new_v
          data[field.name] = new_v

          raise SignatureParseError, 'premature end of signature 0x06' if new_v.bytesize != l_length
        else
          raise SignatureParseError, 'unsupported variable type'
        end
      end
      data.delete(field_num.to_s)
      data
    end

    def is_expired(expiry, signature_time, request_time)
      return false if expiry.nil?

      current_epoch_in_seconds = (Time.now.to_f * 1000).to_i / 1000

      signature_time_expired = (signature_time + expiry) < current_epoch_in_seconds
      request_time_expired = request_time + expiry < current_epoch_in_seconds

      signature_time_expired || request_time_expired
    end

    def get_base(verdict, request_time, signature_time, ip_address, user_agent)
      [verdict, request_time, signature_time, ip_address, user_agent].join("\n")
    end
      
    private def field_type_def(field_id, i)
      if FIELD_IDS[field_id]
        return FIELD_IDS[field_id]
      end
      
      result_type = FIELD_IDS[field_id & 0xC0].type
    
      i_str = SignatureVerifierUtils.pad_start(i.to_s, 2, '0')
      result_name = result_type + i_str
    
      Field.new(result_name, result_type)
    end    
  end
end