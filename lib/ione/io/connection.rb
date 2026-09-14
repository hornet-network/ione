# encoding: utf-8

module Ione
  module Io
    # A wrapper around a socket. Handles connecting to the remote host, reading
    # from and writing to the socket.
    # @since v1.0.0
    class Connection < BaseConnection
      attr_reader :connection_timeout
      attr_reader :deadline

      # @private
      def initialize(host, port, connection_timeout, unblocker, clock, socket_impl=Socket)
        super(host, port, unblocker)
        @connection_timeout = connection_timeout
        @clock = clock
        @deadline = @clock.now + connection_timeout unless connection_timeout == Float::INFINITY
        @socket_impl = socket_impl
        @addrinfos = nil
        @connected_promise = Promise.new
        on_closed(&method(:cleanup_on_close))
      end

      # @private
      def connect
        return @connected_promise.future if closed?

        begin
          unless @addrinfos
            @addrinfos = @socket_impl.getaddrinfo(@host, @port, nil, Socket::SOCK_STREAM)
          end
          unless @io
            _, port, _, ip, address_family, socket_type = @addrinfos.shift
            @sockaddr = @socket_impl.sockaddr_in(port, ip)
            @io = @socket_impl.new(address_family, socket_type, 0)
          end
          unless connected?
            @io.connect_nonblock(@sockaddr)
            @state = CONNECTED_STATE
            @connected_promise.fulfill(self)
          end
        rescue Errno::EISCONN
          @state = CONNECTED_STATE
          @connected_promise.fulfill(self)
        rescue Errno::EINPROGRESS, Errno::EALREADY
          # The deadline is only checked once the socket has reported that it
          # is still connecting, so a handshake that completed just before the
          # deadline (EISCONN above) wins over the timeout.
          if @deadline && @clock.now >= @deadline
            close(ConnectionTimeoutError.new("Could not connect to #{@host}:#{@port} within #{@connection_timeout}s"))
          end
        rescue Errno::EINVAL, Errno::ECONNREFUSED => e
          if @addrinfos.empty?
            close(e)
          else
            @io = nil
            retry
          end
        rescue SystemCallError, IOError => e
          # IOError is raised when the socket is closed from another thread
          # while a connect attempt is in progress.
          close(e)
        rescue SocketError => e
          close(e) || cleanup_on_close(e)
        end
        @connected_promise.future
      end

      private

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
