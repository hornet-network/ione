# encoding: utf-8


module Ione
  module Io
    # @private
    class SslAcceptor < Acceptor
      def initialize(host, port, backlog, unblocker, reactor, ssl_context, socket_impl=nil, ssl_socket_impl=nil)
        super(host, port, backlog, unblocker, reactor, socket_impl)
        @ssl_context = ssl_context
        @ssl_socket_impl = ssl_socket_impl
      end

      private

      # Only the connection construction differs from a plain acceptor, so
      # #read and its error handling stay in the superclass. Accept listeners
      # are notified by the connection once the TLS handshake completes rather
      # than here.
      def handle_connection(client_socket, host, port)
        connection = SslServerConnection.new(client_socket, host, port, @unblocker, @ssl_context, method(:notify_accept_listeners), @ssl_socket_impl)
        @reactor.accept(connection)
      end
    end
  end
end
