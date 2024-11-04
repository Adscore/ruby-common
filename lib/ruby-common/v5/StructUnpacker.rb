require_relative "../common/Exceptions.rb"
require_relative "../common/PhpUnpack.rb"
require_relative "./PhpUnserializer.rb"

require 'msgpack' 
require 'json'

class StructUnpacker
  SERIALIZE_HEADER = "S"
  JSON_HEADER = "J"
  MSG_HEADER = "M"
  RFC3986_HEADER = "H"

  def self.parse_payload(decrypted_payload)
    header = decrypted_payload.to_s[0]

    case header
    when SERIALIZE_HEADER, "Serialize", "serialize"
      return serialize_unpack(decrypted_payload)
    when MSG_HEADER, "Msgpack", "msgpack"
      return msg_unpack(decrypted_payload)
    when JSON_HEADER, "StructJson", "json"
      return json_unpack(decrypted_payload)
    when RFC3986_HEADER, "StructRfc3986", "rfc3986"
      return rfc3986_unpack(decrypted_payload)
    else
      raise StructParseError, "Unsupported struct class #{header}"
    end
  end

  class << self
    private

    def serialize_unpack(buffer)
      raise StructParseError, "Unexpected serializer type" if !buffer.to_s.start_with?(SERIALIZE_HEADER)

      begin
        payload = buffer.to_s[SERIALIZE_HEADER.length..-1]
        return PhpUnserializer.new(payload).unserialize
      rescue StandardError => e
        raise StructParseError, "Error parsing Serialize struct: #{e.message}"
      end
    end

    def json_unpack(payload)
      begin
        str_payload = payload.to_s[1..-1]
        JSON.parse(str_payload)
      rescue JSON::ParserError => e
        raise StructParseError, "Error parsing StructJson struct: #{e.message}"
      end
    end

    def msg_unpack(buffer)
      begin
        slice = buffer[1..-1] 
        return MessagePack.unpack(slice)
      rescue StandardError => e
        raise StructParseError, "Error parsing MsgPack struct: #{e.message}"
      end
    end

    def rfc3986_unpack(data)
      begin
        query_string = data.to_s
        query_string.slice!(0) if query_string.start_with?("H")
        decoded = decode_url(query_string)
        pairs = decoded.split('&')
        result = {}

        pairs.each do |pair|
          key, value = pair.split('=', 2)
          result[key] = value || ""
        end

        result
      rescue StandardError => e
        raise StructParseError, "Error parsing StructRfc3986 struct: #{e.message}"
      end
    end

    def decode_url(encoded_url)
      decoded_url = ""
      i = 0

      while i < encoded_url.length
        c = encoded_url[i]
        if c == '%'
          if i + 2 < encoded_url.length
            hex = encoded_url[i + 1, 2]
            begin
              decoded_url << [hex].pack('H*')
              i += 3
            rescue ArgumentError
              decoded_url << c
              i += 1
            end
          else
            decoded_url << c
            i += 1
          end
        else
          decoded_url << c
          i += 1
        end
      end

      decoded_url
    end
  end
end
