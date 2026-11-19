// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Abblix.Utils;

/// <summary>
/// The message-handler half of protecting a server-initiated request whose address came from outside: it refuses
/// redirects, judges the request's address before every send, and makes every connection to an address it judged,
/// leaving only the policy - which addresses are refused - to the derived handler.
/// </summary>
/// <remarks>
/// Three properties make this the right place for the check rather than a pre-flight in front of the client.
/// <para>
/// Redirects are not followed. A receiver that answers a delivery with a 3xx to an internal address would
/// otherwise have the request re-sent there, past any address the caller vetted, so this is the difference
/// between a check and a bypass. With the follow disabled the 3xx comes back as an ordinary non-success response
/// and the caller decides what to do with it.
/// </para>
/// <para>
/// The host is resolved once per send, every address of that answer is judged, and a connection is only ever made
/// to addresses a send judged under the same rule; a connection the send opens goes to its own answer and no other. A name resolved by a check and then again by the socket can answer a public
/// address to the first and an internal one to the second, so a check of its own resolution judges an address the
/// connection never uses. An address written as a literal is judged as it stands.
/// </para>
/// <para>
/// Each <see cref="OutboundAddressRule"/> gets connections of its own. A connection outlives the send that opened it
/// and carries later requests to the same host without being made again, so a connection opened under a lenient rule,
/// or for a destination permitted outright, would otherwise carry a request whose rule refuses the address it is
/// connected to. The transport goes through no proxy, because a proxy resolves the target itself, and the connection
/// would then be made to the proxy rather than to anything judged here.
/// </para>
/// </remarks>
public abstract class AddressValidatingHttpMessageHandler : DelegatingHandler
{
    private static readonly HttpRequestOptionsKey<JudgedDestination> DestinationOfTheRequest =
        new(typeof(JudgedDestination).FullName!);

    private readonly ResolveHostDelegate _resolveHost;

    /// <summary>
    /// Builds the handler over a transport that follows no redirect, decompresses nothing and resolves every host
    /// through <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>.
    /// </summary>
    protected AddressValidatingHttpMessageHandler()
        : this(null)
    {
    }

    /// <summary>
    /// Builds the handler over a transport that follows no redirect, decompresses nothing and resolves every host
    /// through <paramref name="resolveHost"/>.
    /// </summary>
    /// <param name="resolveHost">
    /// Resolves the host a request is sent to; null for <see cref="Dns.GetHostAddressesAsync(string,
    /// CancellationToken)"/>. Its answer is the one judged and the one connected to.</param>
    protected AddressValidatingHttpMessageHandler(ResolveHostDelegate? resolveHost)
    {
        _resolveHost = resolveHost ?? Dns.GetHostAddressesAsync;
        InnerHandler = new TransportsByRule(this);
    }

    /// <summary>
    /// Judges the request's address as written and throws when it may not be reached. Returning normally lets the
    /// send proceed.
    /// </summary>
    /// <param name="requestUri">The address this request is about to reach.</param>
    /// <param name="cancellationToken">Cancels the check.</param>
    /// <remarks>
    /// What the address says as written - its scheme, its name, an operator's permission. What its host resolves to
    /// is judged by this handler, by the rule <see cref="AddressRuleFor"/> names.
    /// </remarks>
    protected abstract Task GuardAsync(Uri requestUri, CancellationToken cancellationToken);

    /// <summary>
    /// Which addresses a connection made for this request may not be made to.
    /// </summary>
    /// <param name="requestUri">The address this request is about to reach.</param>
    /// <returns>The rule every address the request's host stands for is judged by.</returns>
    /// <remarks>
    /// Asked on the send, in the request's own flow, so anything that flow carries can decide it. Without an override
    /// nothing is refused.
    /// </remarks>
    protected virtual OutboundAddressRule AddressRuleFor(Uri requestUri) => OutboundAddressRule.Unrestricted;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var requestUri = request.RequestUri
            ?? throw new InvalidOperationException("A request through this handler must carry a target URI.");

        await GuardAsync(requestUri, cancellationToken);

        var rule = AddressRuleFor(requestUri);

        // The name the transport connects to, in the form it uses: punycode for an internationalized name
        var host = requestUri.IdnHost;
        var addresses = await AddressesOfAsync(host, rule, cancellationToken);

        var refused = Array.Find(addresses, address => rule.Refuses(address));
        if (refused != null)
        {
            throw new HttpRequestException(
                $"SSRF protection: Hostname '{host}' stands for the address {refused}, which may not be reached");
        }

        request.Options.Set(DestinationOfTheRequest, new JudgedDestination(rule, host, addresses));
        return await base.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// The addresses a connection to <paramref name="host"/> may use: the literal itself, or the resolver's answer.
    /// </summary>
    /// <remarks>
    /// A name that does not resolve is an SSRF refusal only under a rule that refuses something: for a destination
    /// permitted outright it is an ordinary failure to reach it, and a caller telling the two apart by the message
    /// would otherwise report an operator's own service as blocked.
    /// </remarks>
    private async Task<IPAddress[]> AddressesOfAsync(
        string host,
        OutboundAddressRule rule,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var literal))
            return [literal];

        IPAddress[] addresses;
        try
        {
            addresses = await _resolveHost(host, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new HttpRequestException($"{PrefixOf(rule)}Unable to resolve hostname '{host}'", exception);
        }

        if (addresses.Length == 0)
            throw new HttpRequestException($"{PrefixOf(rule)}Hostname '{host}' resolved to no address");

        return addresses;
    }

    /// <summary>
    /// How a failure to resolve is introduced: as a refusal under a rule that refuses, as a plain failure otherwise.
    /// </summary>
    private static string PrefixOf(OutboundAddressRule rule) => rule switch
    {
        OutboundAddressRule.Unrestricted => string.Empty,
        OutboundAddressRule.NoPrivateOrReserved or OutboundAddressRule.NoSpecialPurpose => "SSRF protection: ",
        _ => throw new ArgumentOutOfRangeException(nameof(rule), rule, "An address rule this library does not know."),
    };

    /// <summary>
    /// Opens a connection for the request that made the transport need one, to the addresses its send judged, in the
    /// order the answer gave them.
    /// </summary>
    /// <remarks>
    /// Nothing is resolved here: a second resolution is exactly the answer nobody judged. A connection asked for a host
    /// other than the one the send judged is refused rather than made, since the addresses it carries are not that
    /// host's.
    /// </remarks>
    private async ValueTask<Stream> ConnectAsync(
        OutboundAddressRule rule,
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var endpoint = context.DnsEndPoint;
        if (!context.InitialRequestMessage.Options.TryGetValue(DestinationOfTheRequest, out var destination) ||
            destination.Rule != rule ||
            !IsSameHost(destination.Host, endpoint.Host))
        {
            throw new HttpRequestException(
                $"SSRF protection: No judged address to connect to for '{endpoint.Host}:{endpoint.Port}'");
        }

        var failures = new List<Exception>();
        foreach (var address in destination.Addresses)
        {
            try
            {
                return await DialAsync(new IPEndPoint(address, endpoint.Port), cancellationToken);
            }
            catch (SocketException exception)
            {
                failures.Add(exception);
            }
        }

        throw new AggregateException($"No address of host '{endpoint.Host}' accepted a connection", failures);
    }

    /// <summary>
    /// Whether two spellings name one host: the address form of a URI omits the brackets of an IPv6 literal, which the
    /// transport's endpoint keeps.
    /// </summary>
    private static bool IsSameHost(string judged, string connected)
    {
        if (IPAddress.TryParse(judged, out var judgedAddress))
            return IPAddress.TryParse(connected, out var connectedAddress) && judgedAddress.Equals(connectedAddress);

        return string.Equals(judged, connected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Makes the TCP connection to one judged address.
    /// </summary>
    /// <remarks>
    /// A socket of its own for each address, as a socket whose connection failed is not reusable on every platform.
    /// Virtual so a test can see which address the connection is made to without that address being reachable.
    /// </remarks>
    internal virtual async ValueTask<Stream> DialAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(endpoint, cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds the transport a rule's connections go through: no redirect, no ambient credentials, no cookie jar, no
    /// decompression, no proxy, and every connection made to what the send judged.
    /// </summary>
    internal SocketsHttpHandler TransportFor(OutboundAddressRule rule) => new()
    {
        // Redirects are the bypass this whole type exists to stop: a followed 3xx reaches an address nothing
        // vetted. Disabled, the 3xx surfaces as a response the caller handles.
        AllowAutoRedirect = false,

        // No ambient credentials, so a request cannot authenticate to an internal server by accident.
        Credentials = null,

        // No cookie jar, so a cookie one fetched host set is not sent back to it on the next fetch: the handler
        // is shared by every fetch of its client, and draft-ietf-oauth-client-id-metadata-document section 11.1
        // has an authorization server "avoid sending cookies" when fetching a client's metadata document.
        UseCookies = false,

        // No automatic decompression, so a hostile response cannot spend the caller's memory on a bomb.
        AutomaticDecompression = DecompressionMethods.None,

        // A proxy resolves the target on its own, and the connection below would be made to the proxy: through one,
        // nothing this handler judged would be what the request reached.
        UseProxy = false,

        ConnectCallback = (context, cancellationToken) => ConnectAsync(rule, context, cancellationToken),
    };

    /// <summary>
    /// What a send judged: the rule, the host in the form the transport connects to, and that host's addresses.
    /// </summary>
    private sealed record JudgedDestination(OutboundAddressRule Rule, string Host, IPAddress[] Addresses);

    /// <summary>
    /// The handler under this one: it sends each request through the transport of the rule its send judged it by.
    /// </summary>
    /// <remarks>
    /// A request reaching it unjudged is refused rather than sent through any transport, since whichever it took
    /// would connect by a rule nothing chose for it.
    /// </remarks>
    private sealed class TransportsByRule(AddressValidatingHttpMessageHandler owner) : HttpMessageHandler
    {
        private readonly ConcurrentDictionary<OutboundAddressRule, Lazy<HttpMessageInvoker>> _transports = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (!request.Options.TryGetValue(DestinationOfTheRequest, out var destination))
                throw new InvalidOperationException("A request reached the transport without a judged destination.");

            // HTTP/3 runs over QUIC, whose connections the transport makes without the connection step above, so a
            // request that may be sent over it - asked for, or reached by upgrading - would go to an address nobody
            // judged.
            if (request.Version >= HttpVersion.Version30 ||
                request.VersionPolicy == HttpVersionPolicy.RequestVersionOrHigher)
            {
                throw new HttpRequestException(
                    $"SSRF protection: HTTP version {request.Version} with policy {request.VersionPolicy} may be " +
                    "sent over HTTP/3, whose connections are not made to a judged address");
            }

            var transport = _transports.GetOrAdd(
                destination.Rule,
                rule => new Lazy<HttpMessageInvoker>(() => new HttpMessageInvoker(owner.TransportFor(rule))));

            return transport.Value.SendAsync(request, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (var transport in _transports.Values.Where(transport => transport.IsValueCreated))
                    transport.Value.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
