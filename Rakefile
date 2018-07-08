# frozen_string_literal: true

require "rubocop/rake_task"
RuboCop::RakeTask.new

task(:default).clear
task default: [:rubocop, :spec, "bundler-audit"]

desc "Update and run bundler-audit"
task "bundler-audit" do
  sh "bundle-audit update && bundle-audit check"
end
