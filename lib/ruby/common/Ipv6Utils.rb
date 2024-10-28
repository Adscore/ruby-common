require 'ipaddr'

module IpV6Utils

  def self.validate(ip_address)
    begin
      ip = IPAddr.new(ip_address)
      return ip.ipv6?
    rescue IPAddr::InvalidAddressError
      return false
    end
  end

  def self.abbreviate(ip_address)
    begin
      ip = IPAddr.new(ip_address)

      unless ip.ipv6?
        raise ArgumentError, "Invalid address: #{ip_address}"
      end

      return ip.to_s
    rescue IPAddr::InvalidAddressError
      raise ArgumentError, "Invalid address: #{ip_address}"
    end
  end
end
