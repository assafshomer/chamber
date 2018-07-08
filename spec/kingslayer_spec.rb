# frozen_string_literal: true

require "tempfile"
require "securerandom"

describe "Kingslayer" do
  let(:secret_text) { "Some funky secret 1234567890  66 text !@#%&*()$ +*(_P)&*()*%^%$&%!~@$#~`" }
  let(:source_file_path) { "spec/fixtures/secret.txt" }
  let(:cipher) { Kingslayer::AES.new(password: "foobar") }
  let(:explicit_key) { OpenSSL::Cipher::AES256.new(:CBC).random_key.unpack1("H*") }
  let(:encrypted) { cipher.encrypt(secret_text) }
  let(:encrypted_file) { Tempfile.new("secret.txt#{encrypted_file_suffix}") }
  let(:decrypted_file) { Tempfile.new("secret.txt#{decrypted_file_suffix}") }
  let(:encrypted_file_suffix) { Kingslayer::AES.encrypted_file_suffix }
  let(:decrypted_file_suffix) { Kingslayer::AES.decrypted_file_suffix }

  describe "salt" do
    let(:encrypted) { cipher.encrypt(secret_text, salt: salt) }
    describe "Encrypts/decrypts correctly when supplied salt is too long" do
      let(:salt) { "NaClNaClNaClNaClNaClNaClNaClNaClNaClNaCl" }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "Encrypts/decrypts correctly when supplied salt is too short" do
      let(:salt) { "NaCl" }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "Encrypts/decrypts correctly when supplied salt is Numeric" do
      let(:salt) { 42 }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "Encrypts/decrypts correctly even if idiotic value supplied for salt" do
      let(:salt) { { whoknew: "I'm an idiot" } }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end
  end

  describe "initialization" do
    describe "sets password and iterations to 1 given passord and no iterations" do
      it { expect(cipher.password).to eq("foobar") }
      it { expect(cipher.iter).to eq(1) }
    end

    describe "sets password and iterations when giveb both" do
      let(:cipher) { Kingslayer::AES.new(password: "buzz", iter: 3) }
      it { expect(cipher.password).to eq("buzz") }
      it { expect(cipher.iter).to eq(3) }
    end

    describe "without params sets password to a random key and iter to 1" do
      let(:cipher) { Kingslayer::AES.new }
      it { expect(cipher.hexkey).to be_nil }
      it { expect(cipher.password).not_to be_nil }
      it { expect(cipher.iter).to eq(1) }
    end

    describe "parameters" do
      it "does not raise an error when using just a password" do
        expect { Kingslayer::AES.new(password: "password") }.not_to raise_error
      end

      it "does not raise an error with empty constructor" do
        expect { Kingslayer::AES.new }.not_to raise_error
      end
    end

    describe "setup" do
      it "throws correct exception when decryption string is too short" do
        expect { cipher.decrypt("short") }.to raise_error(ArgumentError)
      end

      describe "setup for encryption sets key and iv" do
        before { cipher.encrypt(secret_text) }
        it { expect(cipher.hexkey).not_to be_nil }
        it { expect(cipher.hexiv).not_to be_nil }
      end
    end
  end

  describe "init with password and iterations" do
    describe "text encryption and decryption" do
      it "works with one instance" do
        expect(cipher.decrypt(encrypted)).to eq(secret_text)
      end

      describe "works with iterations" do
        let(:cipher) { Kingslayer::AES.new(password: "password", iter: 100_000) }
        let(:ct) { cipher.encrypt(secret_text) }
        it { expect(cipher.decrypt(ct)).to eq(secret_text) }
      end

      describe "works with different instances" do
        let(:encryptor) { Kingslayer::AES.new(password: "foobar", iter: 10) }
        let(:decryptor) { Kingslayer::AES.new(password: "foobar", iter: 10) }
        let(:ct) { encryptor.encrypt(secret_text) }
        it { expect(decryptor.decrypt(ct)).to eq(secret_text) }
      end

      describe "OpenSSL compatibility (upto initial garbage)" do
        let(:openssl) do
          `echo "#{encrypted}" | openssl aes-256-cbc -d -K #{cipher.hexkey} -iv #{cipher.hexiv} -a`
        end
        it { expect(clean_openssl_garbage(openssl, secret_text)).to eq(secret_text) }
      end

      describe "repeated calls" do
        let(:duplicate) { cipher.encrypt(secret_text) }
        let(:salted) { cipher.encrypt(secret_text, salt: "foobar") }
        let(:duplicate_salted) { cipher.encrypt(secret_text, salt: "foobar") }
        it { expect(duplicate).not_to eq(encrypted) }

        it "are different even if using the same salt (due to random IV)" do
          expect(salted).not_to eq(duplicate_salted)
        end
      end
    end

    describe "file encryption and decryption" do
      describe "gives back the plaintext" do
        before do
          cipher.encrypt_file(source_file_path, encrypted_file.path)
          cipher.decrypt_file(encrypted_file.path, decrypted_file.path)
        end
        it { expect(FileUtils.cmp(source_file_path, decrypted_file.path)).to be_truthy }
      end

      describe "works with iterations" do
        let(:strong) { Kingslayer::AES.new(password: "password", iter: 100) }
        before do
          strong.encrypt_file(source_file_path, encrypted_file.path)
          strong.decrypt_file(encrypted_file.path, decrypted_file.path)
        end

        it { expect(FileUtils.cmp(source_file_path, decrypted_file.path)).to be_truthy }
      end

      describe "raises if supplied with wrong password or iteration" do
        let(:strong) { Kingslayer::AES.new(password: "password", iter: 10) }
        let(:wrong_itr) { Kingslayer::AES.new(password: "password", iter: 9) }
        let(:wrong_pwd) { Kingslayer::AES.new(password: "passwOrd", iter: 10) }
        let(:good_dec) { Kingslayer::AES.new(password: "password", iter: 10) }
        let(:decrypted_wrong_itr_file_path) { Tempfile.new("secret.txt.enc.dec2").path }
        let(:decrypted_wrong_pwd_file_path) { Tempfile.new("secret.txt.enc.dec3").path }
        before { strong.encrypt_file(source_file_path, encrypted_file.path) }

        it "raises an error when decrypting with wrong number of iterations" do
          expect { wrong_itr.decrypt_file(encrypted_file.path, decrypted_wrong_itr_file_path) }
            .to raise_error("bad decrypt")
        end

        it "raises an error when decrypting with the wrong pwd" do
          expect { wrong_pwd.decrypt_file(encrypted_file.path, decrypted_wrong_pwd_file_path) }
            .to raise_error("bad decrypt")
        end
      end

      describe "OpenSSL compatibility (upto initial garbage)" do
        let(:clean_file_path) { Tempfile.new("clean.dec").path }
        let(:decrypted) { File.read(decrypted_file.path) }
        let(:plaintext) { File.read(source_file_path) }
        let(:k) { cipher.hexkey }
        let(:iv) { cipher.hexiv }
        let(:inp) { encrypted_file.path }
        let(:oup) { decrypted_file.path }
        before do
          cipher.encrypt_file(source_file_path, encrypted_file.path)
          `openssl aes-256-cbc -d -in #{inp} -out #{oup} -K #{k} -iv #{iv} -a`
          File.write(clean_file_path, clean_openssl_garbage(decrypted, plaintext))
        end
        it "is compaitble" do
          expect(FileUtils.cmp(source_file_path, clean_file_path)).to be_truthy
        end
      end
    end
  end

  describe "init with init_key" do
    let(:cipher) { Kingslayer::AES.new(password: explicit_key) }
    describe "text encryption and decryption" do
      it "works with one instance" do
        encrypted = cipher.encrypt(secret_text)
        expect(cipher.decrypt(encrypted)).to eq(secret_text)
      end

      describe "works with different instances" do
        let(:encryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:decryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:enc) { encryptor.encrypt(secret_text) }
        it { expect(decryptor.decrypt(enc)).to eq(secret_text) }
        it { expect(encryptor.iter).to eq(1) }
        it { expect(decryptor.iter).to eq(1) }
      end
    end

    describe "file encryption and decryption" do
      before do
        cipher.encrypt_file(source_file_path, encrypted_file.path)
        cipher.decrypt_file(encrypted_file.path, decrypted_file.path)
      end

      it "works correctly" do
        expect(FileUtils.cmp(source_file_path, decrypted_file.path)).to be_truthy
      end

      describe "raises if supplied with wrong key" do
        let(:encryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:wrong_key) { OpenSSL::Cipher::AES256.new(:CBC).random_key.unpack1("H*") }
        let(:wrong_key_decryptor) { Kingslayer::AES.new(password: wrong_key) }
        let(:wrong_key_decryptor_file) { Tempfile.new("secret.txt.enc.xxx") }
        before do
          encryptor.encrypt_file(source_file_path, encrypted_file.path)
        end

        it "raises when decrypting with a KS instantiated with wrong key" do
          expect do
            wrong_key_decryptor
              .decrypt_file(encrypted_file.path, wrong_key_decryptor_file.path)
          end.to raise_error("bad decrypt")
        end
      end
    end
  end

  def clean_openssl_garbage(plaintext, ciphertext)
    clean = plaintext.chars.select(&:valid_encoding?).join
    position = clean.index(/#{Regexp.escape(ciphertext)}/)
    clean[position..-1]
  end
end
