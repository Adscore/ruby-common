require_relative './v4/Signature4VerifierService.rb'

# Entry point of AdScore signature v4 verification library. It expose verify method allowing to verify
# AdScore signature against given set of ipAddress(es) for given zone.

class Signature4Verifier
  DEFAULT_EXPIRY_TIME_SEC = 60

  # Default request and signature expiration is set to 60s
  #
  # @param signature [String] which we want to verify
  # @param user_agent [String] with full description of user agent like 'Mozilla/5.0 (Linux; Android 9; SM-J530F)...'
  # @param key [String] containing related zone key
  # @param ip_addresses [Array<String>] containing ip4 or ip6 addresses against which we check
  #     signature. Usually, is fulfilled from httpXForwardForIpAddresses or/and remoteIpAddresses
  #     header. All possible ip addresses may be provided at once, in case of correct result,
  #     verifier returns list of chosen ip addresses that matched with the signature.
  # @param expiry [Number] which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds THEN result is expired
  # @param is_key_base64_encoded [Boolean] defining if passed key is base64 encoded or not. Default is set to false.
  # @return [Signature4VerificationResult] verification results
  # @raise [VersionError] if there is an error related to version parsing or compatibility.
  # @raise [ParseError] if there is an error parsing the signature or during decryption process
  # @raise [VerifyError] if there is an error during verify decrypted Signature
  def self.verify(signature, user_agent, key, ip_addresses, expiry: DEFAULT_EXPIRY_TIME_SEC, is_key_base64_encoded: false)
    Signature4VerifierService.verifySignature(signature, user_agent, key, ip_addresses, expiry, is_key_base64_encoded)
  end
end

