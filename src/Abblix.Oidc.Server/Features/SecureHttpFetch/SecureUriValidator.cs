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
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Default <see cref="ISecureUriValidator"/> implementation: applies the scheme allow-list and the
/// internal-hostname / private-or-reserved IP-literal rules from <see cref="SecureHttpFetchOptions"/>.
/// </summary>
public class SecureUriValidator(IOptions<SecureHttpFetchOptions> options) : ISecureUriValidator
{
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
        // A named destination is the one way past everything below, and it is checked first so that it also
        // lifts the scheme restriction: reaching a service inside the network means plain HTTP, and a
        // permission unable to say so would permit nothing.
        if (IsAllowedDestination(uri, options.Value.AllowedDestinations))
            return null;

        if (options.Value.AllowedSchemes is { Length: > 0 } allowedSchemes &&
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
    /// The rules live in <see cref="PrivateNetworks"/>, where every package that must refuse an internal
    /// address reads them, so a name added there takes effect here too.
    /// </remarks>
    public static bool IsInternalHostname(string hostname)
        => PrivateNetworks.IsInternalHostname(hostname);

    /// <summary>
    /// Checks if an IP address is private, loopback, link-local, or otherwise reserved.
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="PrivateNetworks"/> for the same reason as the hostname rules above.
    /// </remarks>
    public static bool IsPrivateOrReservedAddress(IPAddress address)
        => PrivateNetworks.IsPrivateOrReserved(address);
}
