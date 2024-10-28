# Custom exception classes
class VerifyError < StandardError; end
class VersionError < StandardError; end
class ParseError < StandardError; end
class SignatureParseError < ParseError; end
class StructParseError < ParseError; end
class DecryptError < ParseError; end