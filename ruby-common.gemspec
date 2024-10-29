# frozen_string_literal: true

require_relative "lib/ruby-common/version.rb"

Gem::Specification.new do |spec|
  spec.name = "ruby-common"
  spec.version = Ruby::Common::VERSION
  spec.authors = ["Adrian Parzych"]
  spec.email = ["adrian.parzych@iterative.pl"]

  spec.summary = "This library provides various utilities for parsing [Adscore](https://adscore.com) signatures v4 and v5,
and virtually anything that might be useful for customers doing server-side
integration with the service."
  spec.homepage = "https://docs.adscore.com/js-api/#signature-verification.html"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = "https://www.adscore.com/"
  spec.metadata["source_code_uri"] = "https://github.com/Adscore/ruby-common"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # gem dependency
  spec.add_dependency 'rbnacl', "~> 7.1.2"
  spec.add_dependency 'msgpack', "~> 1.7.3"
  spec.add_dependency 'rake', "~> 13.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
