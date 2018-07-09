# frozen_string_literal: true

# Reads user input for encryption and decryption
module Chamber
  require "base64"
  require "openssl"
  require "fileutils"
  require "./lib/crypto_helper.rb"
  include CryptoHelper

  def self.run
    puts "Encrypt or Decrypt? (E/D)"

    if gets.chomp.start_with?("E")
      encrypt_directory(read_encryption_options)
    else
      decrypt_directory(read_decryption_options)
    end
  end

  def self.read_encryption_options
    puts "Enter dir path"
    dir_path = gets.chomp
    puts "Enter Password (optional)"
    password = gets.chomp
    puts "Enter Iterations"
    iterations = gets.chomp.to_i
    {
      dir_path: dir_path,
      password: handle_empty(password),
      iterations: handle_empty(iterations)
    }
  end

  def self.read_decryption_options
    puts "Enter zipped dir file name"
    file_path = gets.chomp
    puts "Enter Password or Key"
    password_or_key = gets.chomp
    puts "Enter Iterations"
    iterations = gets.chomp.to_i
    {
      file_path: file_path,
      password_or_key: handle_empty(password_or_key),
      iterations: handle_empty(iterations)
    }
  end

  def self.handle_empty(input)
    input unless input.to_s.strip.empty?
  end
end
