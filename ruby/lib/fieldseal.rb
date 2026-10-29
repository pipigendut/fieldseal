# frozen_string_literal: true

require_relative "fieldseal/cipher"

begin
  require "rails/railtie"
  require_relative "fieldseal/railtie"
rescue LoadError
  nil
end
