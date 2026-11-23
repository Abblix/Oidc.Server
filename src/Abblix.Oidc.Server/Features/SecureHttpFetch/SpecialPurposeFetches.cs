// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Marks the fetches made for a client resolved from its metadata document, which the SSRF validation holds to the
/// special-purpose address registries as written, and the one fetch of such a document that may reach loopback.
/// </summary>
/// <remarks>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7: the server "MUST NOT fetch a Client ID Metadata Document
/// URL or any URLs contained within a Client ID Metadata Document that resolve to special-use IP addresses as defined
/// in [RFC6890]". The validation every other fetch passes lets the NAT64 prefix reach the public IPv4 address it
/// carries, which an IPv6-only network needs; a fetch made inside a scope opened here refuses it. The scope flows with
/// the call into the outbound handler's send, which picks the rule there, in the request's own flow; the connection is
/// then made by that rule, over connections no fetch outside such a scope shares.
/// <para>
/// The same section makes one exception: "Authorization servers deployed for development or testing purposes MAY relax
/// this restriction to allow fetching from loopback addresses when the authorization server itself is also running on
/// a loopback address and the resolved address matches the same loopback interface." A scope opened by
/// <see cref="Enter(OutboundAddressRule)"/> with <see cref="OutboundAddressRule.NoSpecialPurposeButLoopback"/> is that
/// exception, and every check that would refuse loopback reads it here: the name and literal checks through
/// <see cref="PermitsLoopbackHost"/>, the connection through <see cref="Rule"/>.
/// </para>
/// </remarks>
internal static class SpecialPurposeFetches
{
    private static readonly AsyncLocal<OutboundAddressRule?> Current = new();

    /// <summary>
    /// The rule the fetch being made is held to, or null when it is not one made for a client resolved from its
    /// metadata document.
    /// </summary>
    public static OutboundAddressRule? Rule => Current.Value;

    /// <summary>
    /// Whether the fetch being made is one for a client resolved from its metadata document.
    /// </summary>
    public static bool Active => Current.Value is not null;

    /// <summary>
    /// Opens a scope whose fetches refuse every special-purpose address, until it is disposed.
    /// </summary>
    public static IDisposable Enter() => Enter(OutboundAddressRule.NoSpecialPurpose);

    /// <summary>
    /// Opens a scope whose fetches are held to <paramref name="rule"/>, until it is disposed.
    /// </summary>
    /// <param name="rule"><see cref="OutboundAddressRule.NoSpecialPurpose"/>, or
    /// <see cref="OutboundAddressRule.NoSpecialPurposeButLoopback"/> where <see cref="DocumentRuleAt"/> gives it.</param>
    public static IDisposable Enter(OutboundAddressRule rule)
    {
        var previous = Current.Value;
        Current.Value = rule;
        return new Scope(previous);
    }

    /// <summary>
    /// Opens such a scope for the fetches made on behalf of <paramref name="client"/> when it was resolved from its
    /// metadata document, and none otherwise.
    /// </summary>
    public static IDisposable? For(ClientInfo client) => client.ResolvedFromMetadataDocument ? Enter() : null;

    /// <summary>
    /// The rule a client's metadata document is fetched by at a tenant whose issuer is <paramref name="issuer"/>:
    /// loopback is reached only when the host allows it and that issuer is itself on loopback.
    /// </summary>
    /// <param name="issuer">The tenant's issuer, judged as written, never resolved.</param>
    /// <param name="addresses">The host's
    /// <see cref="ClientIdMetadataDocumentOptions.DocumentAddresses"/>.</param>
    public static OutboundAddressRule DocumentRuleAt(Uri issuer, ClientIdMetadataDocumentAddresses addresses)
        => addresses switch
        {
            ClientIdMetadataDocumentAddresses.PublicOnly => OutboundAddressRule.NoSpecialPurpose,

            ClientIdMetadataDocumentAddresses.AllowLoopback => IsLoopbackHost(issuer)
                ? OutboundAddressRule.NoSpecialPurposeButLoopback
                : OutboundAddressRule.NoSpecialPurpose,

            _ => throw new ArgumentOutOfRangeException(
                nameof(addresses), addresses, "Addresses a metadata document is fetched from that this server does not know."),
        };

    /// <summary>
    /// Whether <paramref name="uri"/> names loopback, by the name <c>localhost</c> or by a loopback literal, inside a
    /// scope that may reach loopback, so the checks refusing such a host by its name or literal let it pass and its
    /// connection is judged by the address it resolves to.
    /// </summary>
    public static bool PermitsLoopbackHost(Uri uri)
        => Current.Value == OutboundAddressRule.NoSpecialPurposeButLoopback && IsLoopbackHost(uri);

    /// <summary>
    /// Whether <paramref name="url"/>, a client identifier URL, names loopback at a tenant whose issuer is
    /// <paramref name="issuer"/> while <paramref name="addresses"/> would reach loopback only for an issuer on loopback,
    /// which that issuer is not.
    /// </summary>
    /// <remarks>
    /// A name resolving to loopback is not seen here: it is refused when the connection is judged.
    /// </remarks>
    public static bool LoopbackWithheldAt(Uri issuer, ClientIdMetadataDocumentAddresses addresses, Uri url)
        => DocumentRuleAt(issuer, addresses) == OutboundAddressRule.NoSpecialPurpose &&
           addresses == ClientIdMetadataDocumentAddresses.AllowLoopback &&
           IsLoopbackHost(url);

    // A server "running on a loopback address" is named by one, so the issuer is judged by its host as written: the
    // name localhost (RFC 6761 section 6.3 has it resolve to loopback), or a loopback literal. IdnHost spells an IPv6
    // literal without its brackets
    private static bool IsLoopbackHost(Uri uri)
        => string.Equals(uri.IdnHost, "localhost", StringComparison.OrdinalIgnoreCase) ||
           (IPAddress.TryParse(uri.IdnHost, out var literal) && PrivateNetworks.IsLoopbackAddress(literal));

    private sealed class Scope(OutboundAddressRule? previous) : IDisposable
    {
        public void Dispose() => Current.Value = previous;
    }
}
