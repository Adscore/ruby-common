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
  # Token
  attr_accessor :token
  # Other, which has not been mapped to a field, or getting error during parsing
  attr_accessor :additional_data

  def initialize(hash)
    @zone_id = hash['zone_id'] ? hash['zone_id'].to_i : nil
    @result = hash['result'] ? hash['result'].to_i : nil
    @verdict = hash['verdict']
    @visitor_user_agent = hash['b.ua']
    @data = hash['data']
    @ipv4_ip = hash['ipv4.ip']
    @ipv4_v = hash['ipv4.v'] ? hash['ipv4.v'].to_i : nil
    @ipv6_ip = hash['ipv6.ip']
    @ipv6_v = hash['ipv6.v'] ? hash['ipv6.v'].to_i : nil
    @cpu_cores = hash['b.cpucores'] ? hash['b.cpucores'].to_i : nil
    @ram = hash['b.ram'] ? hash['b.ram'].to_i : nil
    @tz_offset = hash['b.tzoffset'] ? hash['b.tzoffset'].to_i : nil
    @b_platform = hash['b.platform']
    @platform_v = hash['b.platform.v']
    @gpu = hash['b.gpu']
    @apple_sense = hash['apple_sense']
    @horizontal_resolution = hash['b.sr.w'] ? hash['b.sr.w'].to_i : nil
    @vertical_resolution = hash['b.sr.h'] ? hash['b.sr.h'].to_i : nil
    @true_ua = hash['b.trueua']
    @true_ua_location = hash['b.trueloc.c']
    @true_ua_location_c = hash['b.truech.location.c'] ? hash['b.truech.location.c'].to_i : nil
    @truech_ua = hash['b.truech.ua']
    @truech_arch = hash['b.truech.arch']
    @truech_bitness = hash['b.truech.bitness'] ? hash['b.truech.bitness'].to_i : nil
    @truech_model = hash['b.truech.model']
    @truech_platform = hash['b.truech.platform']
    @truech_platform_v = hash['b.truech.platform.v']
    @truech_full_v = hash['b.truech.full.v']
    @truech_mobile = hash['b.truech.mobile']
    @incognito = hash['incognito']
    @sub_id = hash['sub_id']
    @request_time = hash['requestTime'] ? hash['requestTime'].to_i : nil
    @signature_time = hash['HsignatureTime']
    @token = hash['token']
    @additional_data = hash.reject { |key, _| respond_to?(key) }
  end
end