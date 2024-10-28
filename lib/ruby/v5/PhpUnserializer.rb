class PhpUnserializer
  def initialize(data)
    @data = data
    @index = 0
  end

  def unserialize
    type = @data[@index]
    @index += 2 

    case type
    when 'i' then parse_int
    when 'd' then parse_float
    when 'b' then parse_boolean
    when 's' then parse_string
    when 'a' then parse_array
    when 'O' then parse_object
    else
      raise ArgumentError, "Unsupported type: #{type}"
    end
  end

  private

  def parse_int
    semi_colon_index = @data.index(';', @index)
    int_str = @data[@index...semi_colon_index]
    @index = semi_colon_index + 1
    int_str.to_i
  end

  def parse_float
    semi_colon_index = @data.index(';', @index)
    float_str = @data[@index...semi_colon_index]
    @index = semi_colon_index + 1
    float_str.to_f
  end

  def parse_boolean
    bool_char = @data[@index]
    @index += 2
    bool_char == '1'
  end

  def parse_string
    colon_index = @data.index(':', @index)
    length = @data[@index...colon_index].to_i
    @index = colon_index + 2
    str = @data[@index...@index + length]
    @index += length + 2
    str
  end

  def parse_array
    colon_index = @data.index(':', @index)
    length = @data[@index...colon_index].to_i
    @index = colon_index + 2
    map = {}
    length.times do
      key = unserialize
      value = unserialize
      map[key] = value
    end
    @index += 1 
    map
  end

  def parse_object
    colon_index = @data.index(':', @index)
    class_name_length = @data[@index...colon_index].to_i
    @index = colon_index + 2
    class_name = @data[@index...@index + class_name_length]
    @index += class_name_length + 2

    colon_index = @data.index(':', @index)
    length = @data[@index...colon_index].to_i
    @index = colon_index + 2
    fields = {}
    length.times do
      key = unserialize
      value = unserialize
      fields[key] = value
    end
    @index += 1 

    { class_name => fields }
  end
end