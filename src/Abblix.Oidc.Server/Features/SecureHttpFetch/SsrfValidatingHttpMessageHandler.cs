// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// HTTP message handler that keeps a server-initiated request away from the deployment's own network:
/// 1. Hostname-based blocking (localhost, internal, .local TLDs, etc.)
/// 2. Address-based blocking (private ranges, loopback, link-local) of every address the host resolves to
/// 3. The connection made to one of those judged addresses, so a name answering differently a moment later
///    (DNS rebinding) reaches nothing new
/// </summary>
/// <remarks>
/// Defense-in-depth SSRF protection includes:
/// - Blocking common internal hostnames (localhost, internal, intranet, corp, home, lan)
/// - Blocking internal TLDs (.local, .localhost, .internal, .intranet, .corp, .home, .lan)
/// - Blocking single-label hostnames without dots (typically internal)
/// - Resolution with private IP blocking (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.), done once per send, and
///   a connection made only to addresses a send judged under the same rule
///
/// The synchronous scheme/hostname/IP-literal rules are shared with registration-time validation via
/// <see cref="ISecureUriValidator"/>; the resolution is the base handler's, once per send
/// (<see cref="AddressValidatingHttpMessageHandler"/>), judged by the rule <see cref="AddressRuleFor"/> names.
///
/// Attack scenario prevented:
/// 1. Registration: evil.com resolves to 8.8.8.8 (public IP, passes validation)
/// 2. The attacker's name server answers with a zero TTL, and next time with 127.0.0.1
/// 3. A check resolving the name on its own would see 8.8.8.8 while the socket, resolving again, reached localhost
/// 4. Here the send resolves once and the socket connects to that answer: 127.0.0.1 is refused, 8.8.8.8 is reached
/// </remarks>
/// <param name="options">The deployment's outbound fetch settings.</param>
/// <param name="uriValidator">Applies the synchronous scheme, hostname and IP-literal rules.</param>
/// <param name="resolveHost">
/// Resolves a hostname to its addresses; defaults to <see cref="Dns.GetHostAddressesAsync(string,
/// CancellationToken)"/>. Its answer is the one judged and the one connected to. It exists so the resolved-address
/// branch can be driven in both directions without a live DNS. What this server resolves through is a security
/// decision, so the library's own registration always passes the default: only a caller that builds this handler
/// itself decides otherwise.</param>
public class SsrfValidatingHttpMessageHandler(
    IOptions<SecureHttpFetchOptions> options,
    ISecureUriValidator uriValidator,
    ResolveHostDelegate? resolveHost = null)
    : AddressValidatingHttpMessageHandler(resolveHost, options.Value.OutboundProxy)
{
    /// <summary>
    /// Applies the synchronous scheme, hostname and IP-literal rules immediately before the request leaves. The
    /// base handler owns the no-redirect, no-decompression transport, calls this once per send, and then resolves the
    /// host and judges its addresses by <see cref="AddressRuleFor"/>.
    /// </summary>
    protected override Task GuardAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        // Synchronous policy (scheme, internal hostname, private/reserved IP literal), shared with
        // registration-time validation. A null result means the URI passed these checks.
        var rejection = uriValidator.Validate(requestUri);
        if (rejection != null)
        {
            throw new OutboundAddressRefusedException($"SSRF protection: {rejection}");
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Which addresses this request's connection refuses: none for a destination the host named or when the host
    /// switched the blocking off; every special-purpose one (<see cref="PrivateNetworks.IsSpecialPurposeAddress"/>)
    /// for a fetch made on behalf of a client resolved from its metadata document; otherwise every private or reserved
    /// one (<see cref="PrivateNetworks.IsPrivateOrReservedAddress"/>).
    /// </summary>
    /// <remarks>
    /// A destination the host named is exempt, and it has to be: such a service is reached at a private address by
    /// definition. There is no rebinding to defend against either - the permission names the host, and an attacker
    /// who could change what it resolves to already owns the name.
    /// <para>
    /// Sealed: an override could drop the stricter rule the metadata document clients' fetches are held to
    /// (draft-ietf-oauth-client-id-metadata-document section 10.7), with nothing to show for it. It is read on the
    /// send, in the flow that opened the <see cref="SpecialPurposeFetches"/> scope.
    /// </para>
    /// </remarks>
    protected sealed override OutboundAddressRule AddressRuleFor(Uri requestUri)
    {
        if (!options.Value.BlockPrivateNetworks ||
            SecureUriValidator.IsAllowedDestination(requestUri, options.Value.AllowedDestinations))
        {
            return OutboundAddressRule.Unrestricted;
        }

        return SpecialPurposeFetches.Active
            ? OutboundAddressRule.NoSpecialPurpose
            : OutboundAddressRule.NoPrivateOrReserved;
    }
}
