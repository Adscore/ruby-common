class Signature4VerificationResult
  attr_accessor :score, :verdict, :ip_address, :request_time,
                :signature_time, :expired

  def initialize(score:, verdict:, ip_address:, request_time:, 
                 signature_time:, expired: false)
    @score = score
    @verdict = verdict
    @ip_address = ip_address
    @request_time = request_time
    @signature_time = signature_time
    @expired = expired
  end

  def self.is_expired()
    new(
      score: nil,
      verdict: nil,
      ip_address: nil,
      request_time: nil,
      signature_time: nil,
      expired: true
    )
  end

  def to_h
    {
      score: @score,
      verdict: @verdict,
      ip_address: @ip_address,
      request_time: @request_time,
      signature_time: @signature_time,
      expired: @expired
    }
  end

  def to_s
    "ValidationResult(score: #{@score}, verdict: #{@verdict}, ip_address: #{@ip_address}, request_time: #{@request_time}, signature_time: #{@signature_time}, expired: #{@expired})"
  end
end