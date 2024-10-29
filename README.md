# Ruby::Common

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for parsing [Adscore](https://adscore.com) signatures v4 and v5,
and virtually anything that might be useful for customers doing server-side
integration with the service.

## Compatibility

### Supported Signature v5 algorithms
1. `v5_0200H - OpenSSL CBC, HTTP query`
2. `v5_0200S - OpenSSL CBC, PHP serialize`
3. `v5_0201H - OpenSSL GCM, HTTP query`
4. `v5_0201S - OpenSSL GCM, PHP serialize`
5. `v5_0101H - sodium secretbox, HTTP query`
6. `v5_0101S - sodium secretbox, PHP serialize`
7. `v5_0200J - OpenSSL CBC, JSON`
8. `v5_0201J - OpenSSL GCM, JSON`
9. `v5_0101J - sodium secretbox, JSON`
10. `v5_0101M - sodium secretbox, msgpack`
11. `v5_0200M - OpenSSL CBC, msgpack`
12. `v5_0201M - OpenSSL GCM, msgpack`

### Not supported Signature v5 algorithms

1. `v5_0101I - sodium secretbox, igbinary`
2. `v5_0200I - OpenSSL CBC, igbinary`
3. `v5_0201I - OpenSSL GCM, igbinary`

## Installation

You have several options, but the best ones are:

### Import via rubygems.org
Follow version on: https://rubygems.org/gems/ruby-common

Add this line to your application's Gemfile:
```ruby
gem 'ruby-common', '~> [VERSION]'
```


### Import via github.com
Repo: https://github.com/Adscore/ruby-common

Add this line to your application's Gemfile:
```ruby
 gem "ruby-common", :git => "https://github.com/Adscore/ruby-common"
```


And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install ruby-common

## Usage

### V4 signature decryption

When zone's "Response signature algorithm" is set to "Hashing" or "Signing", it means that V4 signatures are in use. They provide basic means to check incoming traffic for being organic and valuable, but do not carry any additional information.

Following are few quick examples of how to use verifier, first import the entry point for library:



```ruby
require 'ruby-common'

begin
    # Verify with base64 encoded key. No expiry parameter, the default expiry time for requestTime and signatureTime is 60s
    result = Signature4Verifier.verify(
        <signature>,
        <user_agent>,
        <key>,
        [<ip_address>] 
      )
rescue VersionError
    # It means that the signature is not the V5 one, check your zone settings and ensure the signatures 
    # are coming from the chosen zone. 
rescue ParseError
    # It means that the signature metadata is malformed and cannot be parsed, or contains invalid data, 
    # check for corruption underway.
rescue VerifyError
    # Signature could not be verified - usually this is a matter of IP / user agent mismatch (or spoofing). 
    # They must be bit-exact, so even excessive whitespace or casing change can trigger the problem.
end


[..]
require 'ruby-common'

begin
    # Verify with checking if expired and non base64 encoded key
    #
    # IF signatureTime + expiry > CurrentDateInSeconds
    # THEN result.getExpired() = true
    result = Signature4Verifier.verify(
            <signature>,
            <user_agent>,
            <key_none_encoded>,
            [<ip_address>],
            expiry: 120, #signature cant be older than 2 min
            is_key_base64_encoded: False # notify that we use non encoded key
            );
[..]


[..]
require 'ruby-common'

begin
    # Verify against number of ip4 and ip6 addresses
    # (No expiry parameter, the default expiry time for requestTime and signatureTime is 120s)
    result = Signature4Verifier.verify(
        <signature>,
        <user_agent>,
        <key_none_encoded>,
        #Multiple ip addresses either from httpXForwardForIpAddresses and remoteIpAddresses header
        ["73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6"], 
        expiry: 120, #signature cant be older than 2 min
        is_key_base64_encoded: False # notify that we use non encoded key
        );
[..]

```
The `result` is an instance of the [Signature4VerificationResult](lib/ruby-common/v4/Signature4VerificationResult.rb) class.



### V5 signature decryption

V5 is in fact an encrypted payload containing various metadata about the traffic. Its decryption does not rely on IP address 
nor User Agent string, so it is immune for environment changes usually preventing V4 to be even decoded. Judge result is also 
included in the payload, but client doing the integration can make its own decision basing on the metadata accompanying.

Zone has to be set explicitly to V5 signature, if you don't see the option, please contact support as we are rolling this 
mode on customer's demand. The format supports a wide variety of encryption and serialization methods, some of them are included 
in this repository, but it can be extended to fulfill specific needs.

It can be integrated in V4-compatible mode, not making use of any V5 features (see V4 verification):




```ruby
require 'ruby-common'

begin

    # Three things are necessary to verify the signature - at least one IP address in array, User Agent string 
    # and the signature itself. Result is represented by Signature5VerificationResult class.
    result = Signature4Verifier.verify(
        <signature>,
        <user_agent>,
        <key>,
        [<ip_address>] 
      )
rescue VersionError
    # It means that the signature is not the V5 one, check your zone settings and ensure the signatures 
    # are coming from the chosen zone. 
rescue ParseError
    # It means that the signature metadata is malformed and cannot be parsed, or contains invalid data, 
    # check for corruption underway.
rescue VerifyError
    # Signature could not be verified - usually this is a matter of IP / user agent mismatch (or spoofing). 
    # They must be bit-exact, so even excessive whitespace or casing change can trigger the problem.
end
```
The `result` is an instance of the [Signature5VerificationResult](lib/ruby-common/v5/Signature5VerificationResult.rb) class.

The result field score only after a successful verify() call. This is expected behavior, to preserve compliance with V4 behavior - the result is only valid when it's proven belonging to a visitor, in other case will be thrown exception. For custom integrations not relying on built-in verification routines (usually more tolerant), the result is present also in result field, but it's then the integrator's reponsibility to ensure whether it's trusted or not. When desired validation is more strict than the built-in one, the verify() can be called first, and after that any additional verification may take place. 

Note: V4 signature parser also holds the payload, but it does not contain any useful informations, only timestamps and signed strings; especially - it does not contain any Judge result value, it is derived from the signature via several hashing/verification approaches.


## Integration

Any questions you have with custom integration, please contact our support@adscore.com. Please remember that we do
require adequate technical knowledge in order to be able to help with the integration; there are other integration
methods which do not require any, or require very little programming.