# frozen_string_literal: true

# name: discourse-ip-anonymizer
# about: TODO
# meta_topic_id: TODO
# version: 0.0.1
# authors: Discourse
# url: TODO
# required_version: 2.7.0

enabled_site_setting :discourse_ip_anonymizer_enabled

module ::DiscourseIpAnonymizer
  PLUGIN_NAME = "discourse-ip-anonymizer"
end

require_relative "lib/discourse_ip_anonymizer/engine"

after_initialize do
  # Code which should run after Rails has finished booting
end
