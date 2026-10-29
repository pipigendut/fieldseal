# frozen_string_literal: true

require "logger"
require "stringio"
require "active_record"
require_relative "helper"
require "coinx/pii/active_record"

class ActiveRecordTest < Minitest::Test
  def setup
    Coinx::PII.key = TEST_KEY
    @log = StringIO.new
    ActiveRecord::Base.logger = Logger.new(@log)
    ActiveRecord::Base.include Coinx::PII::ActiveRecord
    ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
    ActiveRecord::Schema.define(version: 0) do
      create_table :orangs, force: true do |table|
        table.string :orang_nik
      end
    end
    ActiveRecord::Base.connection.add_index :orangs, :orang_nik, unique: true
    define_model
  end

  def test_round_trip_and_lookup
    nik = "3273010101010001"
    OrangRecord.create!(orang_nik: nik)
    refute_includes @log.string, nik

    loaded = OrangRecord.find_by(orang_nik: nik)
    assert_equal nik, loaded.orang_nik

    stored = ActiveRecord::Base.connection.select_value("SELECT orang_nik FROM orangs")
    assert Coinx::PII.ciphertext?(stored)
    assert_equal Coinx::PII.encrypt(nik, column: "orang_nik"), stored

    assert_raises(ActiveRecord::RecordNotUnique) do
      OrangRecord.create!(orang_nik: nik)
    end
  end

  def test_legacy_plaintext_loads_until_rewritten
    legacy = "3273010101010002"
    ActiveRecord::Base.connection.execute(
      "INSERT INTO orangs (orang_nik) VALUES (#{ActiveRecord::Base.connection.quote(legacy)})"
    )
    row = OrangRecord.order(:id).last
    assert_equal legacy, row.orang_nik
    assert_nil OrangRecord.find_by(orang_nik: legacy)

    raw = row.read_attribute_before_type_cast("orang_nik")
    row.update_column(:orang_nik, Coinx::PII.encrypt(raw, column: "orang_nik"))
    assert_equal legacy, OrangRecord.find_by(orang_nik: legacy).orang_nik
  end

  def define_model
    Object.send(:remove_const, :OrangRecord) if Object.const_defined?(:OrangRecord)
    model = Class.new(ActiveRecord::Base) do
      self.table_name = "orangs"
      encrypts_deterministic :orang_nik
    end
    Object.const_set(:OrangRecord, model)
  end
end
