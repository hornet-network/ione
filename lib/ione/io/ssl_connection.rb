# encoding: utf-8

require 'openssl'


module Ione
  module Io
    # @private
    class SslConnection < BaseConnection
      attr_reader :deadline

      def initialize(host, port, io, unblocker, ssl_context=nil, socket_impl=OpenSSL::SSL::SSLSocket,
                     deadline: nil, clock: Time)
        super(host, port, unblocker, clock: clock)
        @socket_impl = socket_impl
        @ssl_context = ssl_context
        @raw_io = io
        @io = nil
        @deadline = deadline
        @wants_read = false
        @connected_promise = Promise.new
        on_closed(&method(:cleanup_on_close))
      end

      def connect
        return @connected_promise.future if closed? || connected?

        # The deadline is only checked when the handshake reports that it is
        # still pending, so a handshake that completes on this attempt wins.
        if @io.nil?
          @io = @ssl_context ? @socket_impl.new(@raw_io, @ssl_context) : @socket_impl.new(@raw_io)
          @io.sync_close = true if @io.respond_to?(:sync_close=)
        end
        @io.connect_nonblock
        @wants_read = false
        @state = CONNECTED_STATE
        @connected_promise.fulfill(self)
        @connected_promise.future
      rescue IO::WaitReadable
        @wants_read = true
        fail_if_past_deadline
        @connected_promise.future
      rescue IO::WaitWritable
        @wants_read = false
        fail_if_past_deadline
        @connected_promise.future
      rescue => e
        close(e)
        @connected_promise.future
      end

      def to_io
        @raw_io
      end

      if RUBY_ENGINE == 'jruby'
        # JRuby signals a pending handshake with WaitReadable even when the
        # handshake still needs to write, so the direction it reports cannot be
        # used to pick one. Watch both and let the handshake make progress
        # whichever way the socket becomes ready.
        def handshake_wants_read?
          true
        end

        def handshake_wants_write?
          true
        end
      else
        def handshake_wants_read?
          @wants_read
        end

        def handshake_wants_write?
          !@wants_read
        end
      end

      def close(cause=nil)
        closed = super
        if closed
          begin
            @raw_io.close if @raw_io && !@raw_io.closed?
          rescue SystemCallError, IOError
            # The SSL socket normally closes this descriptor through sync_close.
          end
        end
        closed
      end

      if RUBY_ENGINE == 'jruby'
        # @private
        def read
          while true
            new_data = @io.read_nonblock(2**16)
            @data_listener.call(new_data) if @data_listener
          end
        rescue IO::WaitReadable, IO::WaitWritable
          # no more data available
        rescue => e
          close(e)
        end
      else
        # @private
        def read
          read_size = 2**16
          while read_size > 0
            new_data = @io.read_nonblock(read_size)
            @data_listener.call(new_data) if @data_listener
            read_size = @io.pending
          end
        rescue IO::WaitReadable, IO::WaitWritable
          # no more data available
        rescue => e
          close(e)
        end
      end

      private

      def fail_if_past_deadline
        return unless deadline_expired?

        close(ConnectionTimeoutError.new("Could not complete TLS handshake with #{@host}:#{@port} within the connect timeout"))
      end

      def cleanup_on_close(cause)
        if cause && !cause.is_a?(IoError)
          cause = ConnectionError.new(cause.message)
        end
        unless @connected_promise.future.completed?
          @connected_promise.fail(cause)
        end
      end
    end
  end
end
