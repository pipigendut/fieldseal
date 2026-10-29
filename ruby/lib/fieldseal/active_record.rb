# frozen_string_literal: true

require "active_record"

module Fieldseal
  # EncryptedStringType stores a deterministic ciphertext and exposes plaintext on the model.
  # Query binds go through serialize, so find_by and uniqueness send ciphertext to SQL.
  class EncryptedStringType < ActiveRecord::Type::Value
    # column is the database column name mixed into the ciphertext.
    def initialize(column)
      @column = column.to_s
      super()
    end

    def type
      :string
    end

    def cast(value)
      return if value.nil?

      value.to_s
    end

    def serialize(value)
      Fieldseal.encrypt(cast(value), column: @column)
    end

    def deserialize(value)
      return if value.nil?

      Fieldseal.decrypt(value.to_s, column: @column)
    end

    # Legacy plaintext counts as changed so an unchanged NIK is still written as ciphertext.
    def changed_in_place?(raw_old_value, new_value)
      return true if legacy_plaintext?(raw_old_value)

      deserialize(raw_old_value) != new_value
    end

    private

    def legacy_plaintext?(raw_old_value)
      raw_old_value.is_a?(String) && !raw_old_value.empty? && !Fieldseal.ciphertext?(raw_old_value)
    end
  end

  # ActiveRecord adds encrypts_deterministic to each model.
  module ActiveRecord
    extend ActiveSupport::Concern

    class_methods do
      # encrypts_deterministic marks columns whose plaintext is sealed on write and opened on read.
      # Pass database column names. Hash-style where and find_by encrypt the lookup value.
      # A SQL string such as where("orang_nik = ?", nik) does not.
      # A stored value without the v1. prefix is sealed on the next save, even when the plaintext is unchanged.
      def encrypts_deterministic(*names)
        names.each do |name|
          attribute name, EncryptedStringType.new(name)
        end
        before_save { seal_legacy_columns(names) }
      end
    end

    private

    # seal_legacy_columns marks plaintext columns dirty so partial UPDATE includes them.
    def seal_legacy_columns(names)
      names.each do |name|
        raw = read_attribute_before_type_cast(name.to_s)
        next unless raw.is_a?(String)
        next if raw.empty? || Fieldseal.ciphertext?(raw)

        public_send("#{name}_will_change!")
      end
    end
  end
end
