begin
    to_process = []
    h2g = H2.new
    h2g.connect('https://127.0.0.1:8181')
    h2g.send_prefix()
    h2g.send_settings()
    # Ack settings
    while true do
        f = h2g.read(-1)
        p f.to_s
        p f.flags
        if f.type == "SETTINGS" and (f.flags & 1 == 1) then
            next
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
            break
        else
            to_process << f
        end
    end
    to_process.each do |f|
        p f.type
    end

    h2g.send_priority(3, 0, 1, 201)
    h2g.send_priority(5, 0, 0, 101)
    h2g.send_priority(7, 0, 0, 1)
    h2g.send_priority(9, 7, 0, 1)
    h2g.send_priority(11, 3, 0, 1)
    prio_low = H2Priority.new(0, 0, 16)
    prio_high = H2Priority.new(0, 0, 32)
    #sleep 6
    #exit 0
    h2g.getp("/big?1", 15, prio_low)
    h2g.getp("/big?2", 17, prio_high)
    while true
        f = h2g.read(-1)
        puts "type:#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}"
        if f.type == "GOAWAY" then
            puts f.to_s
        end
        if f.type == "DATA" then
            h2g.send_window_update(0, f.len)
            h2g.send_window_update(f.stream_id, f.len)
        end
    end
rescue => e
    p e
end
