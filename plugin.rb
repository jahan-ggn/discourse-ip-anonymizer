# frozen_string_literal: true

# name: discourse-ip-anonymizer
# about: Deterministically anonymizes client IP addresses at request time
# version: 0.0.1
# authors: Jahan Gagan
# url: https://github.com/jahan-ggn/discourse-ip-anonymizer

enabled_site_setting :discourse_ip_anonymizer_enabled

module ::DiscourseIpAnonymizer
  PLUGIN_NAME = "discourse-ip-anonymizer"
  DIGEST_ALGORITHM = "SHA256"

  def self.anonymize_ip_address(ip_string)
    return nil if ip_string.blank?

    secret = SiteSetting.discourse_ip_anonymizer_secret_key
    return nil if secret.blank?

    hmac = OpenSSL::HMAC.hexdigest(DIGEST_ALGORITHM, secret, ip_string.to_s)
    hmac[0..7].scan(/.{2}/).map { |hex| hex.to_i(16) }.join(".")
  end

  module RackRequestIpOverride
    def ip
      original_ip = super
      return original_ip unless SiteSetting.discourse_ip_anonymizer_enabled

      ::DiscourseIpAnonymizer.anonymize_ip_address(original_ip) || original_ip
    end
  end

  module ActionDispatchRemoteIpOverride
    def remote_ip
      original_ip = super
      return original_ip unless SiteSetting.discourse_ip_anonymizer_enabled

      ::DiscourseIpAnonymizer.anonymize_ip_address(original_ip.to_s) || original_ip
    end
  end
end

require_relative "lib/discourse_ip_anonymizer/engine"

after_initialize do
  Rack::Request.prepend(::DiscourseIpAnonymizer::RackRequestIpOverride)
  ActionDispatch::Request.prepend(::DiscourseIpAnonymizer::ActionDispatchRemoteIpOverride)
end