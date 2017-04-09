require 'openssl'

if ARGV[0] == 'parse' then
  rsa = OpenSSL::PKey::RSA.new(File.read(ARGV[1]))
  puts "n = #{rsa.n}"
  puts "e = #{rsa.e}"
elsif ARGV[0] == 'generate' then
  rsa = OpenSSL::PKey::RSA.new()
  print 'p? '
  rsa.p = STDIN.gets.to_i
  print 'q? '
  rsa.q = STDIN.gets.to_i
  print 'e? '
  rsa.e = STDIN.gets.to_i
  rsa.n = rsa.p * rsa.q
  rsa.d = rsa.e.mod_inverse((rsa.p-1) * (rsa.q-1))
  rsa.dmp1 = rsa.d % (rsa.p-1)
  rsa.dmq1 = rsa.d % (rsa.q-1)
  rsa.iqmp = rsa.q.mod_inverse(rsa.p)
  puts rsa.to_pem
elsif ARGV[0] == 'decrypt' then
  rsa = OpenSSL::PKey::RSA.new()
  print 'p? '
  rsa.p = STDIN.gets.to_i
  print 'q? '
  rsa.q = STDIN.gets.to_i
  print 'e? '
  rsa.e = STDIN.gets.to_i
  rsa.n = rsa.p * rsa.q
  rsa.d = rsa.e.mod_inverse((rsa.p-1) * (rsa.q-1))
  rsa.dmp1 = rsa.d % (rsa.p-1)
  rsa.dmq1 = rsa.d % (rsa.q-1)
  rsa.iqmp = rsa.q.mod_inverse(rsa.p)
  puts rsa.private_decrypt(File.read(ARGV[1]))
else
  puts "Usage: ruby #{$0} (parse PEM_FILE | generate | decrypt ENCRYPTED_FILE)"
  abort
end
