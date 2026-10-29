# frozen_string_literal: true

require_relative "helper"

class PIITest < Minitest::Test
  def setup
    Coinx::PII.key = TEST_KEY
  end

  def test_vectors
    file = read_fixture("vectors.json")
    Coinx::PII.key = file.fetch("key_hex")
    derived = Coinx::PII.send(:derive_siv_key, unhex(file.fetch("key_hex")))
    assert_equal file.fetch("derived_key_hex"), derived.unpack1("H*")
    assert_equal "coinx-pii", file.fetch("hkdf_salt")
    assert_equal "aes-256-siv-v1", file.fetch("hkdf_info")

    file.fetch("cases").each do |vector|
      encrypted = Coinx::PII.encrypt(vector.fetch("plaintext"), column: vector.fetch("column"))
      assert_equal vector.fetch("ciphertext"), encrypted, vector.fetch("column")
      opened = Coinx::PII.decrypt(vector.fetch("ciphertext"), column: vector.fetch("column"))
      assert_equal vector.fetch("plaintext"), opened, vector.fetch("column")
    end
  end

  def test_encrypt_rules
    nik = "3273010101010001"
    first = Coinx::PII.encrypt(nik, column: "orang_nik")
    second = Coinx::PII.encrypt(nik, column: "orang_nik")
    assert_equal first, second
    assert_equal first, Coinx::PII.encrypt(first, column: "orang_nik")
    refute_equal first, Coinx::PII.encrypt(nik, column: "orang_npwp_number")
    assert_equal "", Coinx::PII.encrypt("", column: "orang_nik")
    assert_nil Coinx::PII.encrypt(nil, column: "orang_nik")
    assert_equal nik, Coinx::PII.decrypt(nik, column: "orang_nik")

    error = assert_raises(Coinx::PII::Error) do
      Coinx::PII.decrypt(first, column: "orang_npwp_number")
    end
    assert_match "orang_npwp_number", error.message

    assert_raises(Coinx::PII::Error) { Coinx::PII.encrypt(nik, column: "") }
    assert_raises(Coinx::PII::Error) { Coinx::PII.key = "abcd" }
  end
end
