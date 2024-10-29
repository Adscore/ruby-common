require_relative './DecryptResult.rb'

class AbstractSymmetricCrypt
  @@method_size = 2

  def parse(payload, lengths)
    total_length = @@method_size + lengths.values.inject(0) { |sum, value| sum + value }

    raise DecryptError, "Premature data end" if payload.size < total_length

    decrypt_result = DecryptResult.new

    decrypt_result.method = PhpUnpack.unpack("vX", payload)['X'].first

    lengths.each do |key, length|
      bytes_for_key = payload.byteslice(0,length)
      payload.slice!(0,length)
      decrypt_result.byte_buffer_map[key] = bytes_for_key
    end

    decrypt_result.data = payload

    decrypt_result
  end
end