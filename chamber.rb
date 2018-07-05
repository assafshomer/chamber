# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'fileutils'
require './crypto_helper'
include CryptoHelper

puts "Encrypt or Decrypt? (E/D)"

if gets.chomp =~ /\AE/ then
  puts "Enter dir path"
  dir_path = gets.chomp
  puts "Enter Password (optional)"
  password = gets.chomp
  puts "Enter Iterations"
  iterations = gets.chomp.to_i
  enc_opts = { dir_path: dir_path }
  enc_opts[:password] = password unless password.strip.empty?
  enc_opts[:iterations] = iterations unless iterations.to_s.strip.empty?

  encrypt_directory(enc_opts)
else
  puts "Enter zipped dir file name"
  file_path = gets.chomp
  puts "Enter Password or Key"
  password_or_key = gets.chomp
  puts "Enter Iterations"
  iterations = gets.chomp.to_i
  dec_opts = { file_path: file_path }
  dec_opts[:password_or_key] = password_or_key unless password_or_key.strip.empty?
  dec_opts[:iterations] = iterations unless iterations.to_s.strip.empty?

  decrypt_directory(dec_opts)
end
