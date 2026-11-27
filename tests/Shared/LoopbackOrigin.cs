// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Abblix.Tests.Shared;

/// <summary>
/// An HTTP/1.1 origin on the IPv4 loopback that answers every request with one status, 200 unless told
/// otherwise, and keeps the connection open, counting the connections it accepted and recording the first line of
/// every request it answered - which is how it serves as a forward proxy too, whose requests name their target.
/// Given a certificate, it speaks TLS with it on every connection.
/// </summary>
/// <remarks>
/// A real socket rather than a handler standing in for the transport, because what is under test is the connection
/// the transport makes: which address it goes to and which later requests it carries. It listens on the loopback
/// alone, because a listener bound to every interface makes the machine's firewall ask about each test host it runs
/// under.
/// </remarks>
internal sealed class LoopbackOrigin : IDisposable
{
    private const string EndOfHeaders = "\r\n\r\n";

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly byte[] _response;
    private readonly X509Certificate2? _certificate;
    private int _connections;
    private int _requests;

    /// <param name="status">The status line's code and reason, such as <c>302 Found</c>.</param>
    /// <param name="headers">Further header lines, each ending in CRLF.</param>
    /// <param name="certificate">The certificate to serve TLS with, or null for plain HTTP.</param>
    public LoopbackOrigin(string status = "200 OK", string headers = "", X509Certificate2? certificate = null)
    {
        _certificate = certificate;
        _response = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\n{headers}Content-Length: 0{EndOfHeaders}");
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _ = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public int Connections => Volatile.Read(ref _connections);

    public int Requests => Volatile.Read(ref _requests);

    /// <summary>The request line of every request answered, in order, such as <c>GET / HTTP/1.1</c>.</summary>
    public ConcurrentQueue<string> RequestLines { get; } = new();

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException
                                                  or ObjectDisposedException)
            {
                return;
            }

            Interlocked.Increment(ref _connections);
            _ = ServeAsync(socket);
        }
    }

    private async Task ServeAsync(Socket socket)
    {
        await using Stream stream = new NetworkStream(socket, ownsSocket: true);
        var buffer = new byte[8192];
        var received = new StringBuilder();
        try
        {
            var connection = await SecuredAsync(stream);
            while (!_stop.IsCancellationRequested)
            {
                var read = await connection.ReadAsync(buffer, _stop.Token);
                if (read == 0)
                    return;

                received.Append(Encoding.ASCII.GetString(buffer, 0, read));

                // A request carries no body here, so its end is the blank line after its headers
                int end;
                while ((end = received.ToString().IndexOf(EndOfHeaders, StringComparison.Ordinal)) >= 0)
                {
                    var head = received.ToString(0, end);
                    received.Remove(0, end + EndOfHeaders.Length);
                    RequestLines.Enqueue(head.Split("\r\n")[0]);
                    Interlocked.Increment(ref _requests);
                    await connection.WriteAsync(_response, _stop.Token);
                }
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException
                                              or System.Security.Authentication.AuthenticationException)
        {
            // The origin is stopping, the client went away, or it refused this origin's certificate
        }
    }

    /// <summary>
    /// The connection as the client speaks to it: TLS over the socket when the origin has a certificate.
    /// </summary>
    private async Task<Stream> SecuredAsync(Stream stream)
    {
        if (_certificate is null)
            return stream;

        var tls = new SslStream(stream, leaveInnerStreamOpen: false);
        await tls.AuthenticateAsServerAsync(
            new SslServerAuthenticationOptions
            {
                // Offline, so the origin fetches nothing its certificate names while preparing to present it: a test
                // counting what the client fetches would otherwise count the origin's own requests
                ServerCertificateContext = SslStreamCertificateContext.Create(
                    _certificate, additionalCertificates: null, offline: true),
            },
            _stop.Token);
        return tls;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _stop.Dispose();
    }
}
