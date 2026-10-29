# frozen_string_literal: true

require "base64"
require "openssl"

require_relative "pii/version"
require_relative "pii/error"
require_relative "pii/siv"

module Coinx
  # PII encrypts database columns with deterministic AES-256-SIV.
  # Ciphertext matches the Go module github.com/pipigendut/coinx-pii/go/pii.
  module PII
    PREFIX = "v1."
    HKDF_SALT = "coinx-pii"
    HKDF_INFO = "aes-256-siv-v1"

    # key= installs PII_KEY for this process.
    # The value is 32 bytes encoded as 64 hex characters, shared with the Go services.
    # Replacing the key makes existing ciphertext unreadable until those rows are rewritten.
    def self.key=(hex)
      @siv_key = derive_siv_key(decode_key(hex)).freeze
    end

    # ciphertext? reports whether value uses the v1 wire format.
    def self.ciphertext?(value)
      value.is_a?(String) && value.start_with?(PREFIX)
    end

    # encrypt seals plaintext for one database column.
    # column is associated data and must be the database column name.
    # An empty string stays empty. nil stays nil. A value that already starts with v1. is returned unchanged.
    def self.encrypt(value, column:)
      return nil if value.nil?
      raise Error, "plaintext must be a string" unless value.is_a?(String)
      return value if value.empty? || ciphertext?(value)
      raise Error, "column name is empty" if column.to_s.empty?

      sealed = seal(siv_key, value, column.to_s)
      PREFIX + Base64.strict_encode64(sealed)
    end

    # decrypt opens a value written by encrypt.
    # A stored string without the v1. prefix is returned unchanged so older plaintext rows still load.
    def self.decrypt(value, column:)
      return nil if value.nil?
      raise Error, "stored value must be a string" unless value.is_a?(String)
      return value if value.empty? || !ciphertext?(value)
      raise Error, "column name is empty" if column.to_s.empty?

      opened = open_stored(value, column)
      opened.force_encoding(Encoding::UTF_8)
      raise Error, "decrypt failed for column #{column}" unless opened.valid_encoding?

      opened
    end

    def self.open_stored(value, column)
      raw = Base64.strict_decode64(value.delete_prefix(PREFIX))
      unseal(siv_key, raw, column.to_s)
    rescue ArgumentError, DecryptError
      raise Error, "decrypt failed for column #{column}"
    end

    def self.decode_key(hex)
      trimmed = hex.to_s.strip.sub(/\A0x/i, "")
      unless trimmed.match?(/\A[0-9a-fA-F]{64}\z/)
        raise Error, "key must be 64 hex characters"
      end

      [trimmed].pack("H*")
    end

    def self.derive_siv_key(raw)
      OpenSSL::KDF.hkdf(raw, salt: HKDF_SALT, info: HKDF_INFO, length: 64, hash: "SHA256")
    end

    def self.siv_key
      raise Error, "key is not set" if @siv_key.nil?

      @siv_key
    end

    private_class_method :decode_key, :derive_siv_key, :siv_key, :open_stored
  end
end
