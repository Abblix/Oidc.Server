// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

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
/// to addresses a send judged under the same rule; a connection the send opens goes to its own answer and no other.
/// A name resolved by a check and then again by the socket can answer a public address to the first and an internal
/// one to the second, so a check of its own resolution judges an address the connection never uses. An address
/// written as a literal is judged as it stands.
/// </para>
/// <para>
/// Each <see cref="OutboundAddressRule"/> gets connections of its own. A connection outlives the send that opened it
/// and carries later requests to the same host without being made again, so a connection opened under a lenient rule,
/// or for a destination permitted outright, would otherwise carry a request whose rule refuses the address it is
/// connected to.
/// </para>
/// <para>
/// No proxy the system or the environment names is used - not the system's and not one named by <c>HTTP_PROXY</c> or
/// <c>HTTPS_PROXY</c> - because a proxy resolves the target itself and the connection is then made to the proxy
/// rather than to anything judged here. A deployment whose only way out is a forward proxy names one explicitly
/// (<see cref="ForwardProxyAddress"/> says which addresses can name one; user information in it is sent as the
/// proxy's credentials when it asks for them). Its requests then go through that proxy: the addresses this handler's
/// own resolution gives are still judged and refused as above, before the proxy is contacted, but the proxy resolves
/// the name again and may connect somewhere that lookup did not return, so the protection is what this server's own
/// lookup sees and no more. The server must still be able to resolve each target itself: with the proxy as the only
/// route and no outside name resolution, every request is refused.
/// </para>
/// <para>
/// A refusal is thrown as an <see cref="OutboundAddressRefusedException"/>.
/// </para>
/// </remarks>
public abstract class AddressValidatingHttpMessageHandler : DelegatingHandler
{
    private static readonly HttpRequestOptionsKey<JudgedDestination> DestinationOfTheRequest =
        new(typeof(JudgedDestination).FullName!);

    private readonly ResolveHostDelegate _resolveHost;
    private readonly Uri? _proxy;

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
    /// through <paramref name="resolveHost"/>, going through <paramref name="proxy"/> when one is named.
    /// </summary>
    /// <param name="resolveHost">
    /// Resolves the host a request is sent to; null for <see cref="Dns.GetHostAddressesAsync(string,
    /// CancellationToken)"/>. Its answer is the one judged and, without a proxy, the one connected to.</param>
    /// <param name="proxy">
    /// The forward proxy every request goes through, or null for none; what holds either way is stated on this
    /// type.</param>
    protected AddressValidatingHttpMessageHandler(ResolveHostDelegate? resolveHost, Uri? proxy = null)
    {
        _resolveHost = resolveHost ?? Dns.GetHostAddressesAsync;
        _proxy = proxy;
        InnerHandler = new TransportsByRule(this);
    }

    /// <summary>
    /// The TLS options every connection this handler makes starts from: how the server's certificate is validated
    /// and which client certificate is presented.
    /// </summary>
    /// <remarks>
    /// The transports under this handler are its own, so this is where a host configures a guarded client's
    /// certificates, for instance from an <c>IHttpClientFactory</c> handler builder action that finds this handler as
    /// the client's primary handler. Set them before the client's first request: each transport copies these options
    /// when it sends its first request, while the chain policy object stays shared by reference. They change nothing
    /// of which address a connection is made to.
    /// <para>
    /// By default validating a certificate makes no request of its own: the chain is built without downloading a
    /// missing issuer and without checking revocation online, because the addresses those downloads go to are named
    /// by the certificate - that is, by whoever runs the endpoint - and the platform fetches them past this handler.
    /// So an endpoint that serves its certificate without the intermediate certificates is refused on every
    /// platform, and on Windows a public root not yet in the local store is not fetched either and fails as an
    /// untrusted root.
    /// </para>
    /// <para>
    /// A host that needs downloads turns them back on by setting its own
    /// <see cref="SslClientAuthenticationOptions.CertificateChainPolicy"/> here, for instance one with
    /// <see cref="X509ChainPolicy.DisableCertificateDownloads"/> false; its policy is used as it is, and every address
    /// it lets the platform fetch is then reached outside this handler's judgment. While a chain policy is set,
    /// revocation checking follows only its <see cref="X509ChainPolicy.RevocationMode"/>, and
    /// <see cref="SslClientAuthenticationOptions.CertificateRevocationCheckMode"/> has no effect. A new
    /// <see cref="X509ChainPolicy"/> starts with <see cref="X509RevocationMode.Online"/>, so such a policy also fetches
    /// the revocation lists a certificate names unless the host sets its revocation mode too.
    /// </para>
    /// <para>
    /// A client certificate set here is presented to every endpoint the guarded client reaches, and those are
    /// addresses that clients registered, so it shows the host's identity to whoever runs them.
    /// </para>
    /// </remarks>
    public SslClientAuthenticationOptions SslOptions { get; } = new()
    {
        // A client registers an endpoint whose certificate names an internal address as its issuer's location (AIA)
        // or its revocation list's, and the server fetches that address while validating the certificate - a request
        // made by the platform, past every address this handler judges.
        CertificateChainPolicy = new X509ChainPolicy
        {
            DisableCertificateDownloads = true,
            RevocationMode = X509RevocationMode.NoCheck,
        },
    };

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
            throw new OutboundAddressRefusedException(
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
            throw Unresolved(rule, $"Unable to resolve hostname '{host}'", exception);
        }

        if (addresses.Length == 0)
            throw Unresolved(rule, $"Hostname '{host}' resolved to no address", null);

        return addresses;
    }

    /// <summary>
    /// A failure to resolve: a refusal under a rule that refuses, a plain failure to reach the destination otherwise.
    /// </summary>
    private static HttpRequestException Unresolved(OutboundAddressRule rule, string reason, Exception? cause)
        => rule switch
        {
            OutboundAddressRule.Unrestricted => new HttpRequestException(reason, cause),
            OutboundAddressRule.NoPrivateOrReserved or
                OutboundAddressRule.NoSpecialPurpose or
                OutboundAddressRule.NoSpecialPurposeButLoopback => new OutboundAddressRefusedException($"SSRF protection: {reason}", cause),
            _ => throw new ArgumentOutOfRangeException(
                nameof(rule), rule, "An address rule this library does not know."),
        };

    /// <summary>
    /// Opens a connection for the request that made the transport need one, to the addresses its send judged, in the
    /// order the answer gave them.
    /// </summary>
    /// <remarks>
    /// Nothing of the target is resolved here: a second resolution is exactly the answer nobody judged. A connection
    /// asked for a host other than the one the send judged is refused rather than made, since the addresses it carries
    /// are not that host's. The one exception is the proxy the deployment named, which is connected to as named.
    /// </remarks>
    private async ValueTask<Stream> ConnectAsync(
        OutboundAddressRule rule,
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var endpoint = context.DnsEndPoint;
        if (_proxy != null && endpoint.Port == _proxy.Port && IsSameHost(_proxy.IdnHost, endpoint.Host))
        {
            var proxyAddresses = await ProxyAddressesAsync(endpoint.Host, cancellationToken);
            return await DialAnyAsync(endpoint, proxyAddresses, cancellationToken);
        }

        if (!context.InitialRequestMessage.Options.TryGetValue(DestinationOfTheRequest, out var destination) ||
            destination.Rule != rule ||
            !IsSameHost(destination.Host, endpoint.Host))
        {
            throw new OutboundAddressRefusedException(
                $"SSRF protection: No judged address to connect to for '{endpoint.Host}:{endpoint.Port}'");
        }

        return await DialAnyAsync(endpoint, destination.Addresses, cancellationToken);
    }

    /// <summary>
    /// The addresses of the proxy the deployment named: the operator chose it, so it is resolved as named and not
    /// judged by any rule.
    /// </summary>
    private static async Task<IPAddress[]> ProxyAddressesAsync(string host, CancellationToken cancellationToken)
        => IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, cancellationToken);

    /// <summary>
    /// Connects to the first of <paramref name="addresses"/> that accepts, in the order given.
    /// </summary>
    private async ValueTask<Stream> DialAnyAsync(
        DnsEndPoint endpoint,
        IPAddress[] addresses,
        CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        foreach (var address in addresses)
        {
            try
            {
                return await DialAsync(new IPEndPoint(address, endpoint.Port), cancellationToken);
            }
            catch (SocketException exception)
            {
                // An address this host cannot reach - its family switched off here among them - gives way to the next
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
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
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

        // Only the proxy the deployment named, never the system's or the environment's: a proxy resolves the target
        // on its own, so through one the address this handler judged is not necessarily the one reached.
        UseProxy = _proxy != null,
        Proxy = _proxy != null ? new WebProxy(_proxy) { BypassProxyOnLocal = false } : null,

        // The host's certificate settings; the connection step below still decides which address is reached
        SslOptions = SslOptions,

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
                throw new OutboundAddressRefusedException(
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
