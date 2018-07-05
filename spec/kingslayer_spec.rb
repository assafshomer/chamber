
describe "Kingslayer" do
  let(:secret_text) { 'Some funky secret 1234567890  66 text !@#%&*()$ +*(_P)&*()*%^%$&%!~@$#~`' }
  let(:source_file_path) { "spec/fixtures/secret.txt" }
  let(:cipher) { Kingslayer::AES.new(password: "foobar") }
  let(:explicit_key) { OpenSSL::Cipher::AES256.new(:CBC).random_key.unpack('H*')[0] }
  let(:with_key) { Kingslayer::AES.new(password: explicit_key) }
  let(:encrypted) { cipher.encrypt(secret_text) }

  describe "salt" do
    let(:encrypted) { cipher.encrypt(secret_text, salt: salt) }

    describe "when supplied salt is too long, text should still encrypt/decrypt correctly" do
      let(:salt) { 'NaClNaClNaClNaClNaClNaClNaClNaClNaClNaCl' }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "when supplied salt is too short, text should still encrypt/decrypt correctly" do
      let(:salt) { 'NaCl' }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "when number is supplied for salt, text should still encrypt/decrypt correctly" do
      let(:salt) { 42 }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end

    describe "when idiotic value is supplied for salt, text should still encrypt/decrypt correctly" do
      let(:salt) { {:whoknew => "I'm an idiot"} }
      it { expect(cipher.decrypt(encrypted)).to eq(secret_text) }
    end
  end

  describe "initialization" do
    describe "with password and no iterations should give password back and set iterations to 1" do
      it { expect(cipher.password).to eq("foobar") }
      it { expect(cipher.iter).to eq(1) }
    end

    describe "with password and iterations should give both back" do
      let(:cipher) { Kingslayer::AES.new(password: 'buzz', iter: 3) }
      it { expect(cipher.password).to eq("buzz") }
      it { expect(cipher.iter).to eq(3) }
    end

    describe "without params should set password to a random key and iter to 1" do
      let(:cipher) { Kingslayer::AES.new }
      it { expect(cipher.hexkey).to be_nil }
      it { expect(cipher.password).not_to be_nil }
      it { expect(cipher.iter).to eq(1) }
    end

    describe "parameters" do
      it "does not raise an error when using just a password" do
        expect { Kingslayer::AES.new(password: "password") }.not_to raise_error
      end
      it "raises an error when using just iterations" do
        expect { Kingslayer::AES.new(iter: 2) }.to raise_error(Kingslayer::AES.wrong_ks_init_message)
      end
      it "does not raise an error with empty constructor" do
        expect { Kingslayer::AES.new() }.not_to raise_error
      end
    end

    describe "setup" do
      it "throws correct exception when decryption string is too short" do
        expect { cipher.decrypt("short") }.to raise_error(ArgumentError)
      end

      describe "setup for encryption should generate non nil iv and key" do
        before { cipher.encrypt(secret_text) }
        it { expect(cipher.hexkey).not_to be_nil }
        it { expect(cipher.hexiv).not_to be_nil }
      end
    end
  end

  describe "init with password and iterations" do
    describe "text encryption and decryption" do
      it "should work with one instance" do
        expect(cipher.decrypt(encrypted)).to eq(secret_text)
      end

      describe "should work with iterations" do
        let(:strong) { Kingslayer::AES.new(password: "password",iter: 100000) }
        let(:enc) { strong.encrypt(secret_text) }
        it { expect(strong.decrypt(enc)).to eq(secret_text) }
      end

      describe "should work with different instances" do
        let(:encryptor) { Kingslayer::AES.new(password: "foobar",iter: 10) }
        let(:decryptor) { Kingslayer::AES.new(password: "foobar",iter: 10) }
        let(:enc) { encryptor.encrypt(secret_text) }
        it { expect(decryptor.decrypt(enc)).to eq(secret_text) }
      end

      describe "should be compatible with OpenSSL upto initial garbage" do
        let(:hexkey) { cipher.hexkey }
        let(:hexiv) { cipher.hexiv }
        let(:openssl)  do
          cmd = `echo "#{encrypted}" | openssl aes-256-cbc -d -K #{hexkey} -iv #{hexiv} -a`
          clean = cmd.chars.select(&:valid_encoding?).join
          start_position = clean.index(/#{Regexp.escape(secret_text)}/)
          clean[start_position..-1]
        end
        it { expect(openssl).to eq(secret_text) }
      end

      describe "repeated calls " do
        let(:duplicate) { cipher.encrypt(secret_text) }
        let(:salted) { cipher.encrypt(secret_text, salt: 'foobar') }
        let(:duplicate_salted) { cipher.encrypt(secret_text, salt: 'foobar') }
        it "should not be the same" do
          expect(duplicate).not_to eq(encrypted)
        end
        it "should not be the same even if using the same salt (due to random IV)" do
          expect(salted).not_to eq(duplicate_salted)
        end
      end
    end

    describe "file encryption and decryption" do
      let(:encrypted_file_path) { Tempfile.new('secret.txt'+encrypted_file_suffix).path }
      let(:decrypted_file_path) { Tempfile.new('secret.txt'+decrypted_file_suffix).path }
      let(:encrypted_file_suffix) { Kingslayer::AES.encrypted_file_suffix }
      let(:decrypted_file_suffix) { Kingslayer::AES.decrypted_file_suffix }
      describe "should work correctly" do
        before do
          cipher.encrypt_file(source_file_path, encrypted_file_path)
          cipher.df(encrypted_file_path, decrypted_file_path)
        end
        it { expect(FileUtils.cmp(source_file_path,decrypted_file_path)).to be_truthy }
      end
      describe "should work with iterations" do
        let(:strong) { Kingslayer::AES.new(password: "password",iter: 100) }
        let(:encrypted_file_path) { Tempfile.new('secret.txt'+encrypted_file_suffix).path }
        let(:decrypted_file_path) { Tempfile.new('secret.txt'+decrypted_file_suffix).path }
        before do
          strong.ef(source_file_path,encrypted_file_path)
          strong.df(encrypted_file_path, decrypted_file_path)
        end
        it { expect(FileUtils.cmp(source_file_path,decrypted_file_path)).to be_truthy }
      end
      describe "should raise if supplied with wrong password or iteration" do
        let(:strong) { Kingslayer::AES.new(password: "password",iter: 10) }
        let(:wrong_itr) { Kingslayer::AES.new(password: "password",iter: 9) }
        let(:wrong_pwd) { Kingslayer::AES.new(password: "passwOrd",iter: 10) }
        let(:good_dec) { Kingslayer::AES.new(password: "password",iter: 10) }
        let(:encrypted_file_path) { Tempfile.new('secret.txt'+encrypted_file_suffix).path }
        let(:decrypted_file_path) { Tempfile.new('secret.txt'+decrypted_file_suffix).path }
        let(:decrypted_wrong_itr_file_path) { Tempfile.new('secret.txt.enc.dec2').path }
        let(:decrypted_wrong_pwd_file_path) { Tempfile.new('secret.txt.enc.dec3').path }
        before do
          strong.ef(source_file_path,encrypted_file_path)
        end
        it "should not raise an error when using a well instantiated decryptor" do
          expect {good_dec.df(encrypted_file_path, decrypted_file_path)}.not_to raise_error
        end
        it "should raise an error when decrypting with a KS instantiated with the wrong number of iterations" do
          expect {wrong_itr.df(encrypted_file_path, decrypted_wrong_itr_file_path)}.to raise_error('bad decrypt')
        end
        it "should raise an error when decrypting with a KS instantiated with the wrong pwd" do
          expect {wrong_pwd.df(encrypted_file_path, decrypted_wrong_pwd_file_path)}.to raise_error('bad decrypt')
        end
      end

      it "should be compatible with OpenSSL upto initial garbage" do
        encrypted_file_path = Tempfile.new('secret.txt'+Kingslayer::AES.encrypted_file_suffix).path
        cipher.encrypt_file(source_file_path, encrypted_file_path)
        decrypted_file_path = Tempfile.new('secret.txt'+Kingslayer::AES.decrypted_file_suffix).path
        clean_file_path = Tempfile.new('clean.dec').path
        `openssl aes-256-cbc -d -in #{encrypted_file_path} -out #{decrypted_file_path} -K #{cipher.hexkey} -iv #{cipher.hexiv} -a`
        clean = File.read(decrypted_file_path).chars.select(&:valid_encoding?).join
        secret_text = File.read(source_file_path)
        regex = /#{Regexp.escape(secret_text)}/
        start_position = clean.index(regex)
        File.write(clean_file_path,clean[start_position..-1])
        expect(FileUtils.cmp(source_file_path, clean_file_path)).to be_truthy
      end
    end
  end

  describe "init with init_key" do
    subject { with_key }
    describe "text encryption and decryption" do
      it "should work with one instance" do
        encrypted = with_key.e(secret_text)
        with_key.d(encrypted).should == secret_text
      end
      describe "should work with different instances" do
        let(:encryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:decryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:enc) { encryptor.e(secret_text) }
        it { decryptor.d(enc).should == secret_text }
        it {encryptor.iter.should == 1}
        it {decryptor.iter.should == 1}
      end
      it "should be compatible with OpenSSL upto initial garbage" do
        encrypted = with_key.e(secret_text)
        hexkey = with_key.hexkey
        hexiv = with_key.hexiv
        from_openssl = `echo "#{encrypted}" | openssl aes-256-cbc -d -K #{hexkey} -iv #{hexiv} -a`
        # from_openssl.chars.select(&:valid_encoding?).join.should =~ /#{secret_text}/
        clean = from_openssl.chars.select(&:valid_encoding?).join
        regex = /#{Regexp.escape(secret_text)}/
        start_position = clean.index(regex)
        clean[start_position..-1].should == secret_text
      end
      describe "repeated calls " do
        let(:encrypted1) { with_key.e(secret_text) }
        let(:encrypted2) { with_key.e(secret_text) }
        let(:encrypted3) { with_key.e(secret_text, salt: 'foobar') }
        let(:encrypted4) { with_key.e(secret_text, salt: 'foobar') }
        it "should not be the same" do
          encrypted1.should_not == encrypted2
        end
        it "should not be the same even if using the same salt (due to random IV)" do
          encrypted3.should_not == encrypted4
        end
      end
    end

    describe "file encryption and decryption" do
      let(:encrypted_file_path) { Tempfile.new('secret.txt'+encrypted_file_suffix).path }
      let(:decrypted_file_path) { Tempfile.new('secret.txt'+decrypted_file_suffix).path }
      let(:encrypted_file_suffix) { Kingslayer::AES.encrypted_file_suffix }
      let(:decrypted_file_suffix) { Kingslayer::AES.decrypted_file_suffix }
      describe "should work correctly" do
        before do
          with_key.ef(source_file_path, encrypted_file_path)
          with_key.df(encrypted_file_path, decrypted_file_path)
        end
        it { expect(FileUtils.cmp(source_file_path,decrypted_file_path)).to be_truthy }
      end
      describe "should raise if supplied with wrong key" do
        let(:encryptor) { Kingslayer::AES.new(password: explicit_key) }
        let(:wrong_key) { OpenSSL::Cipher::AES256.new(:CBC).random_key.unpack('H*')[0] }
        let(:wrong_key_decryptor) { Kingslayer::AES.new(password: wrong_key) }
        let(:encrypted_file_path) { Tempfile.new('secret.txt'+encrypted_file_suffix).path }
        let(:wrong_key_decryptor_file_path) { Tempfile.new('secret.txt.enc.xxx').path }
        before do
          encryptor.ef(source_file_path,encrypted_file_path)
        end
        it "should raise an error when decrypting with a KS instantiated with the wrong key" do
          expect {wrong_key_decryptor.df(encrypted_file_path, wrong_key_decryptor_file_path)}.to raise_error('bad decrypt')
        end
      end
      it "should be compatible with OpenSSL upto initial garbage" do
        encrypted_file_path = Tempfile.new('secret.txt'+encrypted_file_suffix).path
        with_key.ef(source_file_path, encrypted_file_path)
        decrypted_file_path = Tempfile.new('secret.txt'+decrypted_file_suffix).path
        clean_file_path = Tempfile.new('clean.dec').path
        `openssl aes-256-cbc -d -in #{encrypted_file_path} -out #{decrypted_file_path} -K #{with_key.hexkey} -iv #{with_key.hexiv} -a`
        clean = File.read(decrypted_file_path).chars.select(&:valid_encoding?).join
        secret_text = File.read(source_file_path)
        regex = /#{Regexp.escape(secret_text)}/
        start_position = clean.index(regex)
        File.write(clean_file_path,clean[start_position..-1])
        expect(FileUtils.cmp(source_file_path, clean_file_path)).to be_truthy
      end
    end
  end
end
