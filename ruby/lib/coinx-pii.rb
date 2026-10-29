# frozen_string_literal: true

require_relative "coinx/pii"

begin
  require "rails/railtie"
  require_relative "coinx/pii/railtie"
rescue LoadError
  nil
end
