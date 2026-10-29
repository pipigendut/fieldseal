# frozen_string_literal: true

require_relative "ruby/lib/coinx/pii/version"

Gem::Specification.new do |spec|
  spec.name = "coinx-pii"
  spec.version = Coinx::PII::VERSION
  spec.authors = ["Pipigendut"]
  spec.email = ["pipigendut@users.noreply.github.com"]
  spec.summary = "Deterministic field encryption shared by Coinx Rails and Go services"
  spec.description = "AES-256-SIV for database columns. The same plaintext and column name always produce the same ciphertext, so equality lookups and unique indexes keep working."
  spec.homepage = "https://github.com/pipigendut/coinx-pii"
  spec.license = "LicenseRef-Pipigendut-Internal"
  spec.required_ruby_version = ">= 3.2"
  spec.files = Dir["ruby/lib/**/*.rb", "README.md", "LICENSE", "CHANGELOG.md"]
  spec.require_paths = ["ruby/lib"]
  spec.metadata = {
    "source_code_uri" => "https://github.com/pipigendut/coinx-pii",
    "changelog_uri" => "https://github.com/pipigendut/coinx-pii/blob/main/CHANGELOG.md"
  }
end
