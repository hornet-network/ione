# encoding: utf-8

module Ione
  module Io
    # A wrapper around a socket. Handles connecting to the remote host, reading
    # from and writing to the socket.
    # @since v1.0.0
    class Connection < BaseConnection
      attr_reader :connection_timeout
      attr_reader :deadline

      # Errors that mean this address is no good, but another address from
      # #getaddrinfo might still work.
      RETRIABLE_CONNECT_ERRORS = [Errno::EINVAL, Errno::ECONNREFUSED].freeze

      # @private
      def initialize(host, port, connection_timeout, unblocker, clock, socket_impl=Socket)
        super(host, port, unblocker, clock: clock)
        @connection_timeout = connection_timeout
        @deadline = connection_timeout == Float::INFINITY ? nil : clock.now + connection_timeout
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
            succeed_connection
          end
        rescue Errno::EISCONN
          # The kernel reports the socket as already connected, but on
          # BSD-derived platforms a connect that FAILED asynchronously also
          # reports EISCONN on every subsequent attempt, and the real error is
          # only readable through SO_ERROR. Trust that over EISCONN, otherwise
          # a refused connection is handed to the caller as an established one.
          error = pending_socket_error
          error ? handle_connect_error(error) : succeed_connection
        rescue Errno::EINPROGRESS, Errno::EALREADY
          # The deadline is only checked once the socket has reported that it
          # is still connecting, so a connect that completed just before the
          # deadline wins over the timeout.
          if deadline_expired?
            close(ConnectionTimeoutError.new("Could not connect to #{@host}:#{@port} within #{@connection_timeout}s"))
          end
        rescue SystemCallError, IOError => e
          # IOError is raised when the socket is closed from another thread
          # while a connect attempt is in progress.
          handle_connect_error(e)
        rescue SocketError => e
          close(e) || cleanup_on_close(e)
        end
        @connected_promise.future
      end

      private

      def succeed_connection
        @state = CONNECTED_STATE
        @connected_promise.fulfill(self)
      end

      def handle_connect_error(error)
        if RETRIABLE_CONNECT_ERRORS.any? { |c| error.is_a?(c) } && @addrinfos && !@addrinfos.empty?
          discard_socket
          connect
        else
          close(error)
        end
      end

      # The error left on the socket by a failed asynchronous connect, or nil
      # when the connect really did succeed.
      def pending_socket_error
        code = @io.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
        code.zero? ? nil : SystemCallError.new("connect(2) to #{@host}:#{@port}", code)
      rescue SystemCallError, IOError
        nil
      end

      # Close the socket for the address that just failed before moving on to
      # the next one, otherwise its descriptor leaks until the object is
      # finalized.
      def discard_socket
        begin
          @io.close if @io
        rescue SystemCallError, IOError
          # nothing to do, the socket was most likely already closed
        end
        @io = nil
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
