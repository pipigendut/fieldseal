# frozen_string_literal: true

require_relative "helper"

class SealTest < Minitest::Test
  def setup
    Fieldseal.key = TEST_KEY
  end

  def test_release_version
    assert_equal "0.1.1", Fieldseal::VERSION
    assert_equal "3.2.10", RUBY_VERSION
  end

  def test_vectors
    file = read_fixture("vectors.json")
    Fieldseal.key = file.fetch("key_hex")
    derived = Fieldseal.send(:derive_siv_key, unhex(file.fetch("key_hex")))
    assert_equal file.fetch("derived_key_hex"), derived.unpack1("H*")
    assert_equal "fieldseal", file.fetch("hkdf_salt")
    assert_equal "aes-256-siv-v1", file.fetch("hkdf_info")

    file.fetch("cases").each do |vector|
      encrypted = Fieldseal.encrypt(vector.fetch("plaintext"), column: vector.fetch("column"))
      assert_equal vector.fetch("ciphertext"), encrypted, vector.fetch("column")
      opened = Fieldseal.decrypt(vector.fetch("ciphertext"), column: vector.fetch("column"))
      assert_equal vector.fetch("plaintext"), opened, vector.fetch("column")
    end
  end

  def test_encrypt_rules
    nik = "3273010101010001"
    first = Fieldseal.encrypt(nik, column: "orang_nik")
    second = Fieldseal.encrypt(nik, column: "orang_nik")
    assert_equal first, second
    assert_equal first, Fieldseal.encrypt(first, column: "orang_nik")
    refute_equal first, Fieldseal.encrypt(nik, column: "orang_npwp_number")
    assert_equal "", Fieldseal.encrypt("", column: "orang_nik")
    assert_nil Fieldseal.encrypt(nil, column: "orang_nik")
    assert_equal nik, Fieldseal.decrypt(nik, column: "orang_nik")

    error = assert_raises(Fieldseal::Error) do
      Fieldseal.decrypt(first, column: "orang_npwp_number")
    end
    assert_match "orang_npwp_number", error.message

    assert_raises(Fieldseal::Error) { Fieldseal.encrypt(nik, column: "") }
    assert_raises(Fieldseal::Error) { Fieldseal.key = "abcd" }
  end
end
