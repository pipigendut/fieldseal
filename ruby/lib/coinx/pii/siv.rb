# frozen_string_literal: true

require "openssl"

module Coinx
  module PII
    BLOCK = 16
    private_constant :BLOCK

    def self.dbl(block)
      bytes = block.bytes
      out = Array.new(BLOCK, 0)
      carry = 0
      (BLOCK - 1).downto(0) do |index|
        shifted = bytes[index] >> 7
        out[index] = ((bytes[index] << 1) & 0xff) | carry
        carry = shifted
      end
      out[BLOCK - 1] ^= 0x87 if (bytes[0] & 0x80) != 0
      out.pack("C*")
    end

    def self.xor_bytes(left, right)
      left.bytes.zip(right.bytes).map { |first, second| first ^ second }.pack("C*")
    end

    def self.aes_encrypt_block(key, block)
      cipher = OpenSSL::Cipher.new("AES-#{key.bytesize * 8}-ECB")
      cipher.encrypt
      cipher.padding = 0
      cipher.key = key
      cipher.update(block) + cipher.final
    end

    def self.cmac_subkeys(key)
      stretched = aes_encrypt_block(key, ("\0" * BLOCK).b)
      first = dbl(stretched)
      [first, dbl(first)]
    end

    def self.split_cmac(message, first_key, second_key)
      size = message.bytesize
      if size.positive? && (size % BLOCK).zero?
        head = message.byteslice(0, size - BLOCK)
        last = xor_bytes(message.byteslice(size - BLOCK, BLOCK), first_key)
        return [head, last]
      end

      remainder = size % BLOCK
      head = remainder == size ? +"".b : message.byteslice(0, size - remainder)
      padded = ("\0" * BLOCK).b
      padded[0, remainder] = message.byteslice(size - remainder, remainder) if remainder.positive?
      padded.setbyte(remainder, 0x80)
      [head, xor_bytes(padded, second_key)]
    end

    def self.cbc_mac(key, head, last)
      state = ("\0" * BLOCK).b
      offset = 0
      while offset < head.bytesize
        block = xor_bytes(state, head.byteslice(offset, BLOCK))
        state = aes_encrypt_block(key, block)
        offset += BLOCK
      end
      aes_encrypt_block(key, xor_bytes(state, last))
    end

    def self.aes_cmac(key, message)
      first_key, second_key = cmac_subkeys(key)
      head, last = split_cmac(message, first_key, second_key)
      cbc_mac(key, head, last)
    end

    def self.s2v(mac_key, components)
      if components.empty?
        marker = ("\0" * (BLOCK - 1)).b
        marker << "\x01"
        return aes_cmac(mac_key, marker)
      end

      state = aes_cmac(mac_key, ("\0" * BLOCK).b)
      components[0..-2].each do |component|
        state = xor_bytes(dbl(state), aes_cmac(mac_key, component))
      end
      # A final block of 16 bytes or more is xorend'd with state. A shorter
      # block is padded and xor'd with dbl(state). See RFC 5297 A.1 and A.2.
      aes_cmac(mac_key, s2v_tail(components.last, state))
    end

    def self.s2v_tail(last, state)
      if last.bytesize >= BLOCK
        out = last.dup
        base = out.bytesize - BLOCK
        state.bytes.each_with_index do |byte, index|
          out.setbyte(base + index, out.getbyte(base + index) ^ byte)
        end
        return out
      end

      padded = ("\0" * BLOCK).b
      padded[0, last.bytesize] = last if last.bytesize.positive?
      padded.setbyte(last.bytesize, 0x80)
      xor_bytes(padded, dbl(state))
    end

    def self.clear_counter_bits(synthetic)
      counter = synthetic.dup
      counter.setbyte(8, counter.getbyte(8) & 0x7f)
      counter.setbyte(12, counter.getbyte(12) & 0x7f)
      counter
    end

    def self.split_key(key)
      unless [32, 64].include?(key.bytesize)
        raise Error, "siv key length #{key.bytesize}"
      end

      half = key.bytesize / 2
      [key.byteslice(0, half), key.byteslice(half, half)]
    end

    def self.aes_ctr(key, iv, data)
      return +"".b if data.empty?

      cipher = OpenSSL::Cipher.new("AES-#{key.bytesize * 8}-CTR")
      cipher.encrypt
      cipher.padding = 0
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end

    def self.seal(key, plaintext, *associated)
      mac_key, ctr_key = split_key(key)
      parts = associated.map(&:b) + [plaintext.b]
      synthetic = s2v(mac_key, parts)
      body = aes_ctr(ctr_key, clear_counter_bits(synthetic), plaintext.b)
      synthetic + body
    end

    def self.unseal(key, sealed, *associated)
      raise DecryptError, "decrypt failed" if sealed.bytesize < BLOCK

      mac_key, ctr_key = split_key(key)
      synthetic = sealed.byteslice(0, BLOCK)
      body = sealed.byteslice(BLOCK, sealed.bytesize - BLOCK) || +"".b
      plain = aes_ctr(ctr_key, clear_counter_bits(synthetic), body)
      check = s2v(mac_key, associated.map(&:b) + [plain])
      raise DecryptError, "decrypt failed" unless secure_equal?(check, synthetic)

      plain
    end

    def self.secure_equal?(left, right)
      return false unless left.bytesize == right.bytesize

      OpenSSL.secure_compare(left, right)
    end

    private_class_method :dbl, :xor_bytes, :aes_encrypt_block, :cmac_subkeys, :split_cmac,
                         :cbc_mac, :aes_cmac, :s2v, :s2v_tail, :clear_counter_bits, :split_key,
                         :aes_ctr, :seal, :unseal, :secure_equal?
  end
end
