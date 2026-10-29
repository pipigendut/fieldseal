# frozen_string_literal: true

require "rails/railtie"

module Fieldseal
  # Railtie reads FIELDSEAL_KEY and installs encrypts_deterministic on ActiveRecord::Base.
  class Railtie < Rails::Railtie
    initializer "fieldseal.configure" do
      key = ENV.fetch("FIELDSEAL_KEY", "").strip
      Fieldseal.key = key unless key.empty?
    end

    initializer "fieldseal.active_record" do
      ActiveSupport.on_load(:active_record) do
        require "fieldseal/active_record"
        ::ActiveRecord::Base.include(Fieldseal::ActiveRecord)
      end
    end
  end
end
