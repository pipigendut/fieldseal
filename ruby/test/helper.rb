# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "coinx/pii"

ROOT = File.expand_path("../..", __dir__)
TEST_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

def unhex(value)
  [value].pack("H*")
end

def read_fixture(name)
  JSON.parse(File.read(File.join(ROOT, "testdata", name)))
end
