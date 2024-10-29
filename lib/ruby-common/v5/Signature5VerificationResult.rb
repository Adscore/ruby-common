class Signature5VerificationResult
  # Zone-id
  attr_accessor :zone_id
  # Detection result as number, one of following: 0, 3, 6, 9
  attr_accessor :result
  # Detection result as text, one of following: ok, junk, proxy, bot
  attr_accessor :verdict
  # Visitor's User Agent
  attr_accessor :visitor_user_agent
  # Data
  attr_accessor :data
  # IPv4 address
  attr_accessor :ipv4_ip
  # Number of bytes required for IP matching
  attr_accessor :ipv4_v
  # IPv6 address
  attr_accessor :ipv6_ip
  # Number of left-most bytes of IPv6 address needed to match
  attr_accessor :ipv6_v
  # Number of CPU logical cores gathered from navigator.hardwareConcurrency
  attr_accessor :cpu_cores
  # Amount of RAM memory in GB gathered from navigator.deviceMemory
  attr_accessor :ram
  # Timezone offset from GMT in minutes
  attr_accessor :tz_offset
  # User-Agent Client Hints Platform
  attr_accessor :b_platform
  # Content of Sec-CH-UA-Platform-Version request header
  attr_accessor :platform_v
  # GPU Model obtained from WebGL and WebGPU APIs
  attr_accessor :gpu
  # Detected iPhone/iPad model by Adscore AppleSense
  attr_accessor :apple_sense
  # Physical screen horizontal resolution
  attr_accessor :horizontal_resolution
  # Physical screen vertical resolution
  attr_accessor :vertical_resolution
  # Adscore TrueUA-enriched User-Agent
  attr_accessor :true_ua
  # Adscore True Location Country
  attr_accessor :true_ua_location
  # Adscore True Location Confidence
  attr_accessor :true_ua_location_c
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA
  attr_accessor :truech_ua
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Arch
  attr_accessor :truech_arch
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Bitness
  attr_accessor :truech_bitness
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Model
  attr_accessor :truech_model
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Platform
  attr_accessor :truech_platform
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Platform-Version
  attr_accessor :truech_platform_v
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Full-Version
  attr_accessor :truech_full_v
  # Adscore TrueUA-enriched Client Hints header Sec-CH-UA-Mobile
  attr_accessor :truech_mobile
  # Indicates whether visitor is using Private Browsing (Incognito) Mode
  attr_accessor :incognito
  # Adscore zone subId
  attr_accessor :sub_id
  # Request time
  attr_accessor :request_time
  # Signature time
  attr_accessor :signature_time
  # Signature time
  attr_accessor :h_signature_time
  # Token
  attr_accessor :token
  # Other, which has not been mapped to a field, or getting error during parsing
  attr_accessor :additional_data

  def initialize(hash)
    @zone_id = hash.delete('zone_id')&.to_i
    @result = hash.delete('result')&.to_i
    @verdict = hash.delete('verdict')
    @visitor_user_agent = hash.delete('b.ua')
    @data = hash.delete('data')
    @ipv4_ip = hash.delete('ipv4.ip')
    @ipv4_v = hash.delete('ipv4.v')&.to_i
    @ipv6_ip = hash.delete('ipv6.ip')
    @ipv6_v = hash.delete('ipv6.v')&.to_i
    @cpu_cores = hash.delete('b.cpucores')&.to_i
    @ram = hash.delete('b.ram')&.to_i
    @tz_offset = hash.delete('b.tzoffset')&.to_i
    @b_platform = hash.delete('b.platform')
    @platform_v = hash.delete('b.platform.v')
    @gpu = hash.delete('b.gpu')
    @apple_sense = hash.delete('apple_sense')
    @horizontal_resolution = hash.delete('b.sr.w')&.to_i
    @vertical_resolution = hash.delete('b.sr.h')&.to_i
    @true_ua = hash.delete('b.trueua')
    @true_ua_location = hash.delete('b.trueloc.c')
    @true_ua_location_c = hash.delete('b.truech.location.c')&.to_i
    @truech_ua = hash.delete('b.truech.ua')
    @truech_arch = hash.delete('b.truech.arch')
    @truech_bitness = hash.delete('b.truech.bitness')&.to_i
    @truech_model = hash.delete('b.truech.model')
    @truech_platform = hash.delete('b.truech.platform')
    @truech_platform_v = hash.delete('b.truech.platform.v')
    @truech_full_v = hash.delete('b.truech.full.v')
    @truech_mobile = hash.delete('b.truech.mobile')
    @incognito = hash.delete('incognito')
    @sub_id = hash.delete('sub_id')
    @request_time = hash.delete('requestTime')&.to_i
    @h_signature_time = hash.delete('HsignatureTime')
    @signature_time = hash.delete('signatureTime')
    @token = hash.delete('token')
    @additional_data = hash
  end

  def to_s
    <<~STRING
      Zone ID: #{@zone_id}
      Result: #{@result}
      Verdict: #{@verdict}
      Visitor User Agent: #{@visitor_user_agent}
      Data: #{@data}
      IPv4 IP: #{@ipv4_ip}
      IPv4 Version: #{@ipv4_v}
      IPv6 IP: #{@ipv6_ip}
      IPv6 Version: #{@ipv6_v}
      CPU Cores: #{@cpu_cores}
      RAM: #{@ram}
      Time Zone Offset: #{@tz_offset}
      Browser Platform: #{@b_platform}
      Platform Version: #{@platform_v}
      GPU: #{@gpu}
      Apple Sense: #{@apple_sense}
      Horizontal Resolution: #{@horizontal_resolution}
      Vertical Resolution: #{@vertical_resolution}
      True User Agent: #{@true_ua}
      True User Agent Location: #{@true_ua_location}
      True User Agent Location Code: #{@true_ua_location_c}
      Truech User Agent: #{@truech_ua}
      Truech Architecture: #{@truech_arch}
      Truech Bitness: #{@truech_bitness}
      Truech Model: #{@truech_model}
      Truech Platform: #{@truech_platform}
      Truech Platform Version: #{@truech_platform_v}
      Truech Full Version: #{@truech_full_v}
      Truech Mobile: #{@truech_mobile}
      Incognito: #{@incognito}
      Subscriber ID: #{@sub_id}
      Request Time: #{@request_time}
      Signature Time: #{@signature_time}
      H Signature Time: #{@h_signature_time}
      Token: #{@token}
      Additional Data: #{@additional_data}
    STRING
  end
end