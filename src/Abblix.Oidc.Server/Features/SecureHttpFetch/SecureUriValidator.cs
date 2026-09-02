// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Default <see cref="ISecureUriValidator"/> implementation: applies the scheme allow-list and the
/// internal-hostname / private-or-reserved IP-literal rules from <see cref="SecureHttpFetchOptions"/>.
/// </summary>
/// <remarks>
/// A configuration that lifts the scheme restriction is reported once, when this singleton is
/// created, under this type's own log category. A report rather than a refusal, because an empty
/// list is a statement a deployment may mean; the category makes the message separately silenceable
/// the same way <see cref="SsrfGuardWatch"/>'s is.
/// </remarks>
public partial class SecureUriValidator : ISecureUriValidator
{
    private readonly IOptions<SecureHttpFetchOptions> options;

    /// <summary>
    /// Creates the validator and reports a lifted scheme restriction, once, when the configuration
    /// states one.
    /// </summary>
    /// <param name="options">The fetch policy this validator enforces.</param>
    /// <param name="logger">Carries the one-time report; absent in hosts that build the validator
    /// by hand, where there is nowhere to report to.</param>
    public SecureUriValidator(IOptions<SecureHttpFetchOptions> options, ILogger<SecureUriValidator>? logger = null)
    {
        this.options = options;

        if (options.Value.AllowedSchemes is { Length: 0 } && logger != null)
            LogSchemeRestrictionLifted(logger);
    }

    /// <summary>
    /// Reports whether a URI is one of the destinations named in
    /// <see cref="SecureHttpFetchOptions.AllowedDestinations"/>.
    /// </summary>
    /// <param name="uri">The URI about to be reached.</param>
    /// <param name="allowedDestinations">The configured permissions, which may be absent.</param>
    /// <returns><c>true</c> when the URI matches one of them.</returns>
    /// <remarks>
    /// Static because two separate refusals have to honour the same permission: the synchronous policy
    /// below, and the DNS re-resolution in <see cref="SsrfValidatingHttpMessageHandler"/>. A permission
    /// honoured by only one of them passes validation and then dies at the request - which reads as a
    /// working allow-list in every test of this class, and fails only against a live service.
    /// <para>
    /// An entry with no path of its own (<c>/</c>) matches the whole origin; an entry carrying a path
    /// matches that path exactly. Comparison of scheme and host ignores case as RFC 3986 Section 6.2.2.1
    /// requires, while the path is compared as written, because the same section leaves it case-sensitive.
    /// </para>
    /// </remarks>
    public static bool IsAllowedDestination(Uri uri, Uri[]? allowedDestinations)
        => allowedDestinations is { Length: > 0 } destinations &&
           Array.Exists(destinations, allowed =>
               allowed.IsAbsoluteUri &&
               string.Equals(uri.Scheme, allowed.Scheme, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(uri.Host, allowed.Host, StringComparison.OrdinalIgnoreCase) &&
               uri.Port == allowed.Port &&
               (allowed.AbsolutePath == "/" ||
                string.Equals(uri.AbsolutePath, allowed.AbsolutePath, StringComparison.Ordinal)));

    /// <inheritdoc />
    public string? Validate(Uri uri)
    {
        // Nothing inside this library can reach here with a relative URI, and this is not that guard: an
        // HTTP client with no base address refuses one before the outbound handler is entered, and no
        // registration stores a relative address - which StoredUriValidator holds, and a theory walking
        // the model's URI members by TYPE keeps honest. Not this sentence: the claim was false twice
        // while it read as settled, both times because the list was written by hand - once missing six
        // members with no validator at all, once missing three more whose validator was gated on
        // something that is not the address. What this line defends
        // is the PUBLIC method - a host resolving ISecureUriValidator and asking it about an address of
        // its own - where the alternative is an InvalidOperationException out of a member read below,
        // which is a fault in place of the verdict this method exists to give.
        if (!uri.IsAbsoluteUri)
            return "A relative URI names no destination, so nothing about it can be judged.";

        // A named destination is the one way past everything below, and it is checked first so that it also
        // lifts the scheme restriction: reaching a service inside the network means plain HTTP, and a
        // permission unable to say so would permit nothing.
        if (IsAllowedDestination(uri, options.Value.AllowedDestinations))
            return null;

        if (options.Value.EffectiveAllowedSchemes is { Length: > 0 } allowedSchemes &&
            !allowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            return $"URI scheme '{uri.Scheme}' is not allowed. " +
                   $"Allowed schemes: {string.Join(", ", allowedSchemes)}";
        }

        if (!options.Value.BlockPrivateNetworks)
            return null;

        var hostname = uri.Host;
        if (IsInternalHostname(hostname))
        {
            return $"Hostname '{hostname}' matches internal hostname pattern. " +
                   $"Request blocked to prevent access to internal infrastructure.";
        }

        if (IPAddress.TryParse(hostname, out var ipAddress) && IsPrivateOrReservedAddress(ipAddress))
        {
            return $"IP address '{ipAddress}' is private/internal. " +
                   $"Request blocked to prevent access to internal infrastructure.";
        }

        return null;
    }

    /// <summary>
    /// Checks if a hostname appears to be internal or non-public.
    /// </summary>
    /// <remarks>
    /// The rules live in <see cref="PrivateNetworks"/>, where every package that must refuse such an address
    /// reads them, so a name added there takes effect here too. The wording of this member is kept as shipped:
    /// it is public, and a rename would break a host that calls it for nothing but a synonym.
    /// </remarks>
    public static bool IsInternalHostname(string hostname)
        => PrivateNetworks.IsPrivateHostname(hostname);

    /// <summary>
    /// Checks if an IP address is private, loopback, link-local, or otherwise reserved.
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="PrivateNetworks"/> for the same reason as the hostname rules above.
    /// </remarks>
    public static bool IsPrivateOrReservedAddress(IPAddress address)
        => PrivateNetworks.IsPrivateOrReservedAddress(address);
}
