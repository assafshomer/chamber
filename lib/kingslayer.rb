# frozen_string_literal: true

# Encrypts and Decrypts text, files and directories using AES256
module Kingslayer
  require "openssl"
  require "base64"

  # Encrypts and Decrypts with AES256 in CBC mode with salt and random IV
  class AES
    attr_reader :cipher, :password, :iterations, :hexkey, :hexiv

    def initialize(opts = {})
      @iterations = [(opts[:iterations]).to_i, 1].max
      @password = opts[:password] || generate_256_bit_key
      @cipher = OpenSSL::Cipher::AES256.new("CBC")
    end

    def encrypt(data, opts = {})
      salt = generate_salt(opts[:salt])
      key = stretch_password(password, iterations, salt)
      iv = cipher.random_iv
      setup_cipher(:encrypt, key, iv)
      e = cipher.update(data) + cipher.final
      e = "Salted__#{salt}#{iv}#{e}"
      Base64.encode64(e)
    end

    def decrypt(ciphertext)
      raise ArgumentError, "Data is too short" unless ciphertext.length >= 16
      salt, iv, ct = extract_meta(ciphertext).values
      key = stretch_password(password, iterations, salt)
      setup_cipher(:decrypt, key, iv)
      cipher.update(ct) + cipher.final
    end

    def extract_meta(ct)
      raw = Base64.decode64(ct)
      { salt: raw[8..15], iv: raw[16..31], ct: raw[32..-1] }
    end

    def encrypt_file(plaintext_file_path, encrypted_file_path)
      plaintext = File.read(plaintext_file_path)
      ciphertext = encrypt(plaintext)
      File.write(encrypted_file_path, ciphertext)
    end

    def decrypt_file(encrypted_file_path, decrypted_file_path)
      ciphertext = File.read(encrypted_file_path)
      plaintext = decrypt(ciphertext)
      File.write(decrypted_file_path, plaintext)
    end

    def self.wrong_ks_init_message
      "Iteration number can only be provided with a password"
    end

    def self.short_efs
      ".enc"
    end

    def self.txt_suffix
      ".txt"
    end

    def self.short_dfs
      ".dec"
    end

    def self.encrypted_file_suffix
      "#{short_efs}#{txt_suffix}"
    end

    def self.decrypted_file_suffix
      "#{encrypted_file_suffix}#{short_dfs}"
    end

    private

    def generate_salt(supplied_salt)
      return supplied_salt.to_s[0, 8].ljust(8, ".") if supplied_salt
      (1..8).map { rand(255).chr }.join
    end

    def stretch_password(password, iterations, salt)
      digest = OpenSSL::Digest::SHA256.new
      len = digest.digest_length
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, len, digest)
    end

    def setup_cipher(method, key, iv)
      cipher.send(method)
      cipher.key = key
      @hexkey = key.unpack1("H*")
      cipher.iv = iv
      @hexiv = iv.unpack1("H*")
    end

    def generate_256_bit_key
      OpenSSL::Cipher::AES256.new(:CBC).random_key.unpack1("H*")
    end

    def proper_256_key?(string)
      string.match(/^\h{64}$/).to_s == string
    end
  end
end
