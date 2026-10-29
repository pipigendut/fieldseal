# frozen_string_literal: true

module Fieldseal
  # VERSION is the release consumers pin with a git tag: tag v0.1.1 is gem version 0.1.1.
  # The string is read from the repository VERSION file so the Go module cannot drift.
  VERSION = File.read(File.expand_path("../../../VERSION", __dir__)).strip.freeze
end
