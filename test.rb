# usage: h2get test.rb <url> <path>

url = ARGV[0] || "https://www.google.com"
path = ARGV[1] || "/"

h2g = H2.new
h2g.connect(url)
h2g.send_prefix()
h2g.send_settings()
frame = h2g.read(-1)
puts frame
h2g.send_settings_ack()
(1..2).each {
    h2g.get("/")
    frame = h2g.read(-1)
    puts frame
}
frame = h2g.read(-1)
puts frame

puts "OK"
