class DecryptResult
  def initialize
    @method = nil
    @byte_buffer_map = {}
    @data = nil
  end

  def method
    @method
  end

  def method=(method)
    @method = method
  end

  def byte_buffer_map
    @byte_buffer_map
  end

  def data
    @data
  end

  def data=(data)
    @data = data
  end
end