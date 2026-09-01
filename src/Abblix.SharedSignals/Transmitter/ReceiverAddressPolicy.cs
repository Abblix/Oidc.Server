// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        return JudgeByName(endpoint, out var refusal)
            ? refusal
            : await ResolvedRejectionOf(endpoint, cancellationToken);
    }

    /// <summary>
    /// Why this transmitter will never deliver to the address AS WRITTEN, or null when its name alone
    /// gives no reason to refuse.
    /// </summary>
    /// <param name="endpoint">The endpoint a receiver proposed for its stream.</param>
    /// <remarks>
    /// <para>
    /// This is the question a REGISTRATION may answer, and it is a strict prefix of
    /// <see cref="RejectionOf"/> rather than a second copy of it - so the two cannot come to disagree,
    /// which is the whole reason there is one policy and not a rule restated at each call site.
    /// </para>
    /// <para>
    /// Everything judged here is fixed the moment the receiver names the address: an operator's
    /// permission, the scheme, a hostname spelling out this deployment's own network, an IP literal.
    /// None of it can change between registration and delivery, so accepting such an address and then
    /// refusing every push tells the receiver nothing the transmitter did not already know.
    /// </para>
    /// <para>
    /// Resolution is deliberately NOT part of it. A name is resolved again for every pass, so an answer
    /// given now says nothing about the next one - and a resolver that is briefly down is a condition an
    /// operator recovers from, which delivery treats as one by holding the queue. Answered at
    /// registration the identical fact becomes a terminal refusal, and a receiver registering while its
    /// own DNS record is still propagating cannot tell that from a permanent misconfiguration.
    /// </para>
    /// </remarks>
    public string? RejectionOfName(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        // Undecided reads as "no reason to refuse" here: the remaining question belongs to delivery.
        return JudgeByName(endpoint, out var refusal) ? refusal : null;
    }

    /// <summary>
    /// Judges what the address itself settles, and says whether it settled anything.
    /// </summary>
    /// <returns>
    /// True when the name decides the outcome - <paramref name="refusal"/> then carries the reason, or
    /// null for an address permitted outright. False when only resolution can answer.
    /// </returns>
    /// <remarks>
    /// Three outcomes rather than two, because "permitted outright" and "nothing decided" are different
    /// things and collapsing them costs one of them: an operator's allow-list entry and a public IP
    /// literal are FINAL, so folding them into "undecided" would send an allowed private address on to
    /// be resolved and refused for being private - which is what the allow-list exists to prevent.
    /// </remarks>
    private bool JudgeByName(Uri endpoint, out string? refusal)
    {
        refusal = null;

        if (options.AllowedReceiverAddresses is { Count: > 0 } allowed
            && allowed.Any(permitted => IsSameOrigin(endpoint, permitted)))
        {
            // An operator naming a destination outranks everything below, and it has to: a receiver deployed
            // inside the same network is reached at a private address by definition.
            return true;
        }

        if (endpoint.Scheme != Uri.UriSchemeHttps)
        {
            refusal = $"delivery over '{endpoint.Scheme}' is refused: a security event token carries claims about "
                + "a subject, and cleartext exposes them to anyone on the path";
            return true;
        }

        if (PrivateNetworks.IsPrivateHostname(endpoint.Host))
        {
            refusal = $"the host '{endpoint.Host}' names the deployment's own network rather than a public receiver";
            return true;
        }

        if (IPAddress.TryParse(endpoint.Host, out var literal))
        {
            refusal = PrivateNetworks.IsPrivateOrReservedAddress(literal)
                ? $"the address '{literal}' is private or reserved"
                : null;
            return true;
        }

        return false;
    }

    /// <summary>Why the addresses this name resolves to are unusable, or null when they are not.</summary>
    /// <remarks>
    /// Resolved at delivery rather than at configuration time, because the name is resolved again for
    /// every delivery and an answer that passed once says nothing about what it resolves to now.
    /// </remarks>
    private async Task<string?> ResolvedRejectionOf(Uri endpoint, CancellationToken cancellationToken)
    {
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
