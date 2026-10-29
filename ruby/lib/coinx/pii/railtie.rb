# frozen_string_literal: true

require "rails/railtie"

module Coinx
  module PII
    # Railtie reads PII_KEY and installs encrypts_deterministic on ActiveRecord::Base.
    class Railtie < Rails::Railtie
      initializer "coinx_pii.configure" do
        key = ENV.fetch("PII_KEY", "").strip
        PII.key = key unless key.empty?
      end

      initializer "coinx_pii.active_record" do
        ActiveSupport.on_load(:active_record) do
          require "coinx/pii/active_record"
          ::ActiveRecord::Base.include(PII::ActiveRecord)
        end
      end
    end
  end
end
