require 'stringio'

module PhpUnpack
  NAME = "name"
  CODE = "code"

  def self.unpack(format, input, byte_slice = true)
    instructions = format.split('/')
    offset = 0
    result = {}

    instructions.each do |instruction|
      code_and_name = get_code_and_name(instruction)
      code = code_and_name[CODE]
      name = code_and_name[NAME]

      decoded_data, bytes_offset = decode(input, code)
      result[name] = decoded_data
      offset = offset + bytes_offset
      
      if byte_slice
        input.slice!(0, bytes_offset)
      end
    end
    result
  end

  def self.decode(input, code)
    case code
    when 'c'
      decoded_data = input.unpack('c')
      bytes_offset = 1
    when 'C'
      decoded_data = input.unpack('C')
      bytes_offset = 1
    when 'n'
      decoded_data = input.unpack('n')
      bytes_offset = 2
    when 'N'
      decoded_data = input.unpack('N')
      bytes_offset = 4
    when 'J'
      decoded_data = input.unpack1('Q>')
      bytes_offset = 8
    when 'v'
      decoded_data = input.unpack('v')
      bytes_offset = 2
    else
      raise ArgumentError, "Unrecognized instruction: #{code}"
    end

    [decoded_data, bytes_offset]
  end

  def self.pack(format, *inputs)
    instructions = format.split('')
    raise ArgumentError, "Invalid format length, expected #{inputs.length} number of codes" unless instructions.length == inputs.length

    buffer = StringIO.new
    instructions.each_with_index do |code, i|
      encoded_data = encode(inputs[i], code)
      buffer.write(encoded_data)
    end

    buffer.string
  end

  def self.encode(input, code)
    case code
    when 'c'
      [input.to_i].pack('c')
    when 'C'
      [input.to_i].pack('C')
    when 'n'
      [input.to_i].pack('n')
    when 'N'
      [input.to_i].pack('N')
    when 'J'
      [input.to_i].pack('J')
    when 'v'
      [input.to_i].pack('v')
    else
      raise ArgumentError, "Unrecognized instruction: #{code}"
    end
  end

  private

  def self.get_code_and_name(instruction)
    raise ArgumentError, "Empty instruction" if instruction.nil? || instruction.empty?

    code = instruction[0]
    name = instruction[1..-1]
    { CODE => code, NAME => name }
  end
end