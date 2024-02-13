$file_handle = nil

def say_hi1
  puts 'hi'
  $file_handle = File.open "/"
end

def e
  say_hi1
end

def d
  e
end

def c
  d
end

def b
  c
end

def a
  b
end

def say_hi2
  puts 'hi2'
  $file_handle&.close
end

def c2
  say_hi2
end

def b2
  c2
end

def a2
  b2
end

$stdout.sync = true
puts "PID: #{Process.pid}"

while true
  a
  sleep 0.05
  a2
  sleep 0.05
end
