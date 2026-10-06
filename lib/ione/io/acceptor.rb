# encoding: utf-8


module Ione
  module Io
    # An acceptor wraps a server socket and accepts client connections.
    # @since v1.1.0
    class Acceptor
      # @private
      ServerSocket = RUBY_ENGINE == 'jruby' ? ::ServerSocket : Socket

      BINDING_STATE = 0
      CONNECTED_STATE = 1
      CLOSED_STATE = 2

      attr_reader :backlog

      # @private
      def initialize(host, port, backlog, unblocker, reactor, socket_impl=nil)
        @host = host
        @port = port
        @backlog = backlog
        @unblocker = unblocker
        @reactor = reactor
        @io = nil
        @socket_impl = socket_impl || ServerSocket
        @accept_listeners = []
        @lock = Mutex.new
        @state = BINDING_STATE
      end

      # Register a listener to be notified when client connections are accepted
      #
      # @yieldparam [Ione::Io::ServerConnection] the connection to the client
      def on_accept(&listener)
        @lock.synchronize do
          @accept_listeners << listener
        end
      end

      # @private
      def bind
        addrinfos = @socket_impl.getaddrinfo(@host, @port, nil, Socket::SOCK_STREAM)
        begin
          _, port, _, ip, address_family, socket_type = addrinfos.shift
          @io = @socket_impl.new(address_family, socket_type, 0)
          bind_socket(@io, @socket_impl.sockaddr_in(port, ip), @backlog)
        rescue Errno::EADDRNOTAVAIL => e
          if addrinfos.empty?
            raise
          else
            retry
          end
        end
        @state = CONNECTED_STATE
        Future.resolved(self)
      rescue => e
        close
        Future.failed(e)
      end

      # Stop accepting connections
      def close
        @lock.synchronize do
          return false if @state == CLOSED_STATE
          @state = CLOSED_STATE
        end
        if @io
          begin
            @io.close
          rescue SystemCallError, IOError
            # nothing to do, the socket was most likely already closed
          ensure
            @io = nil
          end
        end
        # Wake the reactor so it stops selecting on the closed descriptor,
        # otherwise the listening port can stay bound until the next wakeup.
        @unblocker.unblock
        true
      end

      # @private
      alias_method :drain, :close

      # @private
      def to_io
        @io
      end

      # Returns true if the acceptor has stopped accepting connections
      def closed?
        @state == CLOSED_STATE
      end

      # Returns true if the acceptor is accepting connections
      def connected?
        @state != CLOSED_STATE
      end

      # @private
      def connecting?
        false
      end

      # @private
      def writable?
        false
      end

      # @private
      def deadline
        nil
      end

      # @private
      def handshake_wants_read?
        false
      end

      # @private
      def handshake_wants_write?
        false
      end

      # @private
      def read
        client_socket, host, port = accept
        return if client_socket.nil?
        handle_connection(client_socket, host, port)
      end

      if RUBY_ENGINE == 'jruby'
        # @private
        def bind_socket(socket, addr, backlog)
          socket.bind(addr, backlog)
        end
      else
        # @private
        def bind_socket(socket, addr, backlog)
          socket.bind(addr)
          socket.listen(backlog)
        end
      end

      private

      # Conditions that mean "no connection to accept this time". They clear on
      # their own because whatever was pending is gone, so the acceptor stays
      # registered and tries again on the next tick. Anything else, in
      # particular resource exhaustion such as EMFILE, is left to propagate:
      # it does not clear by itself, and swallowing it would turn the reactor
      # into a silent busy loop instead of reporting through #on_error.
      TRANSIENT_ACCEPT_ERRORS = [
        Errno::EAGAIN,
        Errno::EWOULDBLOCK,
        Errno::EINTR,
        Errno::ECONNABORTED,
        Errno::EPROTO,
      ].uniq.freeze

      # Returns nil when nothing was accepted. Shared by every subclass, so
      # that TLS acceptors get the same error handling as plain ones.
      def accept
        client_socket, client_sockaddr = @io.accept_nonblock
        port, host = @socket_impl.unpack_sockaddr_in(client_sockaddr)
        return client_socket, host, port
      rescue IOError, Errno::EBADF
        # the listening socket was closed from another thread while the
        # reactor was about to accept on it
        close
        nil
      rescue *TRANSIENT_ACCEPT_ERRORS
        nil
      end

      def handle_connection(client_socket, host, port)
        connection = ServerConnection.new(client_socket, host, port, @unblocker)
        @reactor.accept(connection)
        notify_accept_listeners(connection)
      end

      def notify_accept_listeners(connection)
        listeners = @lock.synchronize { @accept_listeners }
        listeners.each { |l| l.call(connection) rescue nil }
      end
    end
  end
end
