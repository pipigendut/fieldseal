# frozen_string_literal: true

module Coinx
  module PII
    # Error is raised when the key is missing, the key is malformed, or ciphertext cannot be opened.
    class Error < StandardError; end

    # DecryptError is the authentication failure from AES-SIV, before it is wrapped for callers.
    class DecryptError < Error; end
  end
end
