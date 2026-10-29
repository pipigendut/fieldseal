# frozen_string_literal: true

require_relative "helper"

class SIVTest < Minitest::Test
  def test_cmac_rfc4493
    read_fixture("rfc4493.json").fetch("cases").each do |vector|
      mac = Fieldseal.send(:aes_cmac, unhex(vector.fetch("key")), unhex(vector.fetch("message")))
      assert_equal vector.fetch("mac"), mac.unpack1("H*"), vector.fetch("name")
    end
  end

  def test_siv_rfc5297
    read_fixture("rfc5297.json").fetch("cases").each do |vector|
      key = unhex(vector.fetch("key"))
      plaintext = unhex(vector.fetch("plaintext"))
      associated = vector.fetch("ads").map { |item| unhex(item) }
      sealed = Fieldseal.send(:seal, key, plaintext, *associated)
      assert_equal vector.fetch("output"), sealed.unpack1("H*"), vector.fetch("name")
      opened = Fieldseal.send(:unseal, key, sealed, *associated)
      assert_equal plaintext, opened, vector.fetch("name")
    end
  end

  def test_aes256_round_trip
    key = ("\x11" * 64).b
    [0, 1, 15, 16, 17, 40].each do |size|
      plaintext = ("a" * size).b
      sealed = Fieldseal.send(:seal, key, plaintext, "orang_nik")
      opened = Fieldseal.send(:unseal, key, sealed, "orang_nik")
      assert_equal plaintext, opened, "size #{size}"
      assert_raises(Fieldseal::DecryptError) do
        Fieldseal.send(:unseal, key, sealed, "orang_name")
      end
    end
  end
end
