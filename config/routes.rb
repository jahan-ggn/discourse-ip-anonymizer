# frozen_string_literal: true

DiscourseIpAnonymizer::Engine.routes.draw do
  get "/examples" => "examples#index"
  # define routes here
end

Discourse::Application.routes.draw { mount ::DiscourseIpAnonymizer::Engine, at: "discourse-ip-anonymizer" }
