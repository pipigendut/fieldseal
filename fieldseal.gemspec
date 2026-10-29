# frozen_string_literal: true

require_relative "ruby/lib/fieldseal/version"

Gem::Specification.new do |spec|
  spec.name = "fieldseal"
  spec.version = Fieldseal::VERSION
  spec.authors = ["Pipigendut"]
  spec.email = ["pipigendut@users.noreply.github.com"]
  spec.summary = "Deterministic field encryption shared by Rails and Go services"
  spec.description = "AES-256-SIV for database columns. The same plaintext and column name always produce the same ciphertext, so equality lookups and unique indexes keep working."
  spec.homepage = "https://github.com/pipigendut/fieldseal"
  spec.license = "LicenseRef-Pipigendut-Internal"
  # Reject every other Ruby. A service bump requires a new fieldseal release first.
  spec.required_ruby_version = "= 3.2.10"
  spec.files = Dir["ruby/lib/**/*.rb", "README.md", "LICENSE", "CHANGELOG.md", "VERSION"]
  spec.require_paths = ["ruby/lib"]
  spec.metadata = {
    "source_code_uri" => "https://github.com/pipigendut/fieldseal",
    "changelog_uri" => "https://github.com/pipigendut/fieldseal/blob/main/CHANGELOG.md"
  }
end
