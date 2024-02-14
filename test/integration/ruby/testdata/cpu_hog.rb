def cpu
  (0..1000).each do
  end
end

def c1
  cpu
end

def b1
  c1
end

def a1
  b1
end

$stdout.sync = true
puts "PID: #{Process.pid}"

while true
  a1
end
