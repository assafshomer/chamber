# frozen_string_literal: true

module CryptoHelper
	require 'fileutils'
	require './kingslayer.rb'
	include Kingslayer
	PBKDF2_ITERATIONS = 10
	ENCRYPTED_FILE_SUFFIX = ".enc"
	DECRYPTED_FILE_SUFFIX = ".dec"

	def encrypt(opts = {})
		password, file_path = opts[:password], opts[:file_path]
		raise "Cannot encrypt #{file_path}. File does not exist" unless File.exist?(file_path)
		params = { password: password, iter: opts[:iterations] || PBKDF2_ITERATIONS } if password
		ks = Kingslayer::AES.new(params.to_h)
		path = ks.encrypt_file(file_path, file_path + ENCRYPTED_FILE_SUFFIX)
		puts "Your file was encrypted to #{path}"
		puts "Your file was encrypted with #{ks.password}" unless password
	end

	def decrypt(opts = {})
		password_or_key, file_path = opts[:password_or_key], opts[:file_path]
		raise "Cannot decrypt #{file_path}. No password or key was provided" unless password_or_key
		raise "Cannot decrypt #{file_path}. File does not exist" unless File.exist?(file_path)

		begin
			ks = Kingslayer::AES.new(password: password_or_key)
			ks.decrypt_file(file_path, file_path + DECRYPTED_FILE_SUFFIX)
		rescue
			iterations = opts[:iterations] || PBKDF2_ITERATIONS
			ks = Kingslayer::AES.new(password: password_or_key, iter: iterations)
			ks.decrypt_file(file_path, file_path + DECRYPTED_FILE_SUFFIX)
		end
	end

	def encrypt_directory(opts = {})
		dir_path = opts[:dir_path]
		raise "Cannot encrypt #{dir_path}. Directory does not exist" unless File.directory?(dir_path)
		zipped_filename = dir_path.split("/").reject(&:empty?).join("-") + ".zip"
		`zip -r #{zipped_filename} #{dir_path}`
		encryption_options = { file_path: zipped_filename }
		encryption_options[:password] ||= opts[:password]
		encryption_options[:iterations] ||= opts[:iterations]
		encrypt(encryption_options)
		FileUtils.rm_rf dir_path
		FileUtils.rm_f zipped_filename
	end

	def decrypt_directory(opts = {})
		puts "decryption options are: #{opts}"
		decrypted_file_path = decrypt(opts)
		zipped_filename = decrypted_file_path.gsub(".enc.dec", "")
		FileUtils.mv(decrypted_file_path, zipped_filename)
		`unzip #{zipped_filename}`
		FileUtils.rm_f zipped_filename
		FileUtils.rm_f opts[:file_path]
	end

	def stretch_key(password, iter, salt)
		digest = OpenSSL::Digest::SHA256.new
		len = digest.digest_length
		OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter, len, digest)
	end
end
