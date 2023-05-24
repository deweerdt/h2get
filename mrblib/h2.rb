class H2
  attr_reader :current_conn

  [
    :expect_prefix,
    :send_prefix,
    :expect_prefix,
    :send_prefix,
    :send_settings,
    :send_settings_ack,
    :send_priority,
    :send_ping,
    :send_rst_stream,
    :send_window_update,
    :send_goaway,
    :send_raw_frame,
    :get,
    :getp,
    :send_headers,
    :send_data,
    :send_continuation,
    :on_settings,
    :read,
    :close,
  ].each do |meth|
    define_method(meth) do |*args|
      if @current_conn.nil?
        raise 'no available connection'
      end
      @current_conn.__send__(meth, *args)
    end
  end
end
