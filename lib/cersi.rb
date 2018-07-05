module Cersi
  require 'openssl'
  require 'encryptor'

  def stretch_password(password, iterations, salt)
    return unless password
    digest = OpenSSL::Digest::SHA256.new
    length = digest.digest_length
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, length, digest)
  end

  def encrypt(secret, opts)
    password = opts[:password]
    iterations = opts[:iterations]
    key = stretch_password(password, iterations) || 
    iv = SecureRandom.random_bytes(12)
    salt = SecureRandom.random_bytes(16)
    Encryptor.encrypt(value: secret, key: key, iv: iv, salt: salt)
  end
end
