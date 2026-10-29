# frozen_string_literal: true

require "active_record"

module Coinx
  module PII
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
        PII.encrypt(cast(value), column: @column)
      end

      def deserialize(value)
        return if value.nil?

        PII.decrypt(value.to_s, column: @column)
      end

      def changed_in_place?(raw_old_value, new_value)
        deserialize(raw_old_value) != new_value
      end
    end

    # ActiveRecord adds encrypts_deterministic to each model.
    module ActiveRecord
      extend ActiveSupport::Concern

      class_methods do
        # encrypts_deterministic marks columns whose plaintext is sealed on write and opened on read.
        # Pass database column names. Hash-style where and find_by encrypt the lookup value.
        # A SQL string such as where("orang_nik = ?", nik) does not.
        def encrypts_deterministic(*names)
          names.each do |name|
            attribute name, EncryptedStringType.new(name)
          end
        end
      end
    end
  end
end
