// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Net.Sockets;
using Abblix.Utils;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Decides whether the transmitter may deliver to the address a receiver put in its stream configuration.
/// </summary>
/// <remarks>
/// A receiver names its own delivery endpoint (SSF 1.0 Section 8.1.1.1), so that address is input from outside,
/// and the transmitter POSTs security event tokens to it. Without this check a receiver could point a stream at a
/// cloud metadata service and have the transmitter fetch it, which is server-side request forgery with the
/// transmitter's own network position.
/// <para>
/// The rules about which addresses are internal are shared with every other outbound caller in this family, so
/// they come from <see cref="PrivateNetworks"/> rather than being restated here.
/// </para>
/// </remarks>
/// <param name="options">The deployment's transmitter settings, including the operator's allow-list.</param>
/// <param name="resolveHost">
/// Resolves a hostname to its addresses; defaults to <see cref="Dns.GetHostAddressesAsync(string,
/// CancellationToken)"/>. A test supplies its own so the resolved-address branch, the only part of this policy
/// that is not a string comparison, can be driven in both directions without a live DNS.</param>
public sealed class ReceiverAddressPolicy(
    SharedSignalsTransmitterOptions options,
    ReceiverAddressPolicy.HostResolver? resolveHost = null)
{
    /// <summary>
    /// Resolves a hostname to the addresses a connection to it would use.
    /// </summary>
    /// <param name="host">The hostname to resolve.</param>
    /// <param name="cancellationToken">Cancels the resolution.</param>
    public delegate Task<IPAddress[]> HostResolver(string host, CancellationToken cancellationToken);

    private readonly HostResolver _resolveHost = resolveHost ?? Dns.GetHostAddressesAsync;

    /// <summary>
    /// Judges the address of a delivery endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint a receiver configured for its stream.</param>
    /// <param name="cancellationToken">Cancels the name resolution.</param>
    /// <returns>Null when delivery may proceed; otherwise why it may not, in a form fit for a log.</returns>
    public async Task<string?> RejectionOf(Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        if (options.AllowedReceiverAddresses is { Count: > 0 } allowed
            && allowed.Any(permitted => IsSameOrigin(endpoint, permitted)))
        {
            // An operator naming a destination outranks everything below, and it has to: a receiver deployed
            // inside the same network is reached at a private address by definition.
            return null;
        }

        if (endpoint.Scheme != Uri.UriSchemeHttps)
        {
            return $"delivery over '{endpoint.Scheme}' is refused: a security event token carries claims about "
                + "a subject, and cleartext exposes them to anyone on the path";
        }

        if (PrivateNetworks.IsPrivateHostname(endpoint.Host))
        {
            return $"the host '{endpoint.Host}' names the deployment's own network rather than a public receiver";
        }

        if (IPAddress.TryParse(endpoint.Host, out var literal))
        {
            return PrivateNetworks.IsPrivateOrReservedAddress(literal)
                ? $"the address '{literal}' is private or reserved"
                : null;
        }

        // Resolved here rather than at configuration time, because the name is resolved again for every delivery
        // and an answer that passed once says nothing about what it resolves to now.
        IPAddress[] addresses;
        try
        {
            addresses = await _resolveHost(endpoint.Host, cancellationToken);
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException)
        {
            return $"the host '{endpoint.Host}' does not resolve: {exception.Message}";
        }

        // Every answer has to be acceptable, not just the first: a name answering with one public address and one
        // private address would otherwise be reachable by whichever the connection happened to pick.
        var refused = Array.Find(addresses, PrivateNetworks.IsPrivateOrReservedAddress);
        return refused is null
            ? null
            : $"the host '{endpoint.Host}' resolves to '{refused}', which is private or reserved";
    }

    private static bool IsSameOrigin(Uri endpoint, Uri permitted)
        => permitted.IsAbsoluteUri
           && string.Equals(endpoint.Scheme, permitted.Scheme, StringComparison.OrdinalIgnoreCase)
           && string.Equals(endpoint.Host, permitted.Host, StringComparison.OrdinalIgnoreCase)
           && endpoint.Port == permitted.Port;
}
