# spec/string_calculator_spec.rb
require "encryptor"
require "securerandom"
require "./cersi.rb"
include Cersi

describe Kingslayer do
  let(:cipher) { OpenSSL::Cipher.new('aes-256-cbc') }
  let(:iv) { SecureRandom.random_bytes(12) }
  let(:salt) { SecureRandom.random_bytes(16) }
  let(:secret) { "my secret string" }
  let(:ciphertext) { Encryptor.encrypt(value: secret, key: key, iv: iv, salt: salt) }
  describe "Random Key" do
    let(:key) { cipher.random_key }
    before { cipher.encrypt }

    describe 'Encryption' do
      it "encrypts a secret" do
        expect(ciphertext.bytesize).to be_positive
      end
    end

    describe 'Decryption' do
      let(:decryption) { Encryptor.decrypt(value: ciphertext, key: key, iv: iv, salt: salt) }
      it "decrypts the secret" do
        expect(decryption).to eq(secret)
      end
    end
  end

  describe "PBKDF" do
    let(:password) { "my not so strong password" }
    let(:iterations) { 2 }
    let(:key) { stretch_password(password, iterations, salt) }
    let(:ciphertext) { Encryptor.encrypt(value: secret, key: key, iv: iv, salt: salt) }
    before { cipher.encrypt }

    describe 'Encryption' do
      it "encrypts a secret" do
        expect(ciphertext.bytesize).to be_positive
      end
    end

    describe 'Decryption' do
      let(:decryption) { Encryptor.decrypt(value: ciphertext, key: key, iv: iv, salt: salt) }
      it "decrypts the secret" do
        expect(decryption).to eq(secret)
      end
    end
  end
end
