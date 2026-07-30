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
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// HTTP message handler that prevents SSRF attacks through comprehensive validation:
/// 1. Hostname-based blocking (localhost, internal, .local TLDs, etc.)
/// 2. DNS resolution and IP-based blocking (private ranges, loopback, link-local)
/// 3. Re-validation immediately before HTTP request to prevent DNS rebinding (TOCTOU attacks)
/// </summary>
/// <remarks>
/// Defense-in-depth SSRF protection includes:
/// - Blocking common internal hostnames (localhost, internal, intranet, corp, home, lan)
/// - Blocking internal TLDs (.local, .localhost, .internal, .intranet, .corp, .home, .lan)
/// - Blocking single-label hostnames without dots (typically internal)
/// - DNS resolution with private IP blocking (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
/// - Protection against DNS rebinding where attacker changes DNS between validation and request
///
/// The synchronous scheme/hostname/IP-literal rules are shared with registration-time validation via
/// <see cref="ISecureUriValidator"/>; the DNS re-resolution below is unique to the request path.
///
/// Attack scenario prevented:
/// 1. Initial validation: evil.com resolves to 8.8.8.8 (public IP, passes validation)
/// 2. DNS TTL expires (low TTL like 1 second)
/// 3. Attacker changes DNS: evil.com now resolves to 127.0.0.1
/// 4. HTTP request: Without this handler, request would go to localhost
/// 5. With this handler: DNS is re-validated, private IP detected, request blocked
/// </remarks>
public class SsrfValidatingHttpMessageHandler(
    IOptions<SecureHttpFetchOptions> options,
    ISecureUriValidator uriValidator) : DelegatingHandler(
    new HttpClientHandler
    {
        // CRITICAL: Disable automatic redirects to prevent SSRF bypass via redirect chains
        // Attackers could redirect from public URL to private network (e.g., 169.254.169.254)
        AllowAutoRedirect = false,

        // Use system default credentials (none) - prevent NTLM auth to internal servers
        UseDefaultCredentials = false,

        // Disable decompression to prevent zip bomb attacks
        AutomaticDecompression = DecompressionMethods.None,
    })
{
    /// <summary>
    /// Sends HTTP request with comprehensive SSRF validation immediately before making the request.
    /// Validates both hostname patterns and DNS resolution to prevent SSRF and DNS rebinding attacks.
    /// </summary>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        if (uri == null)
        {
            throw new InvalidOperationException("Request URI cannot be null");
        }

        // Synchronous policy (scheme, internal hostname, private/reserved IP literal), shared with
        // registration-time validation. A null result means the URI passed these checks.
        var rejection = uriValidator.Validate(uri);
        if (rejection != null)
        {
            throw new HttpRequestException($"SSRF protection: {rejection}");
        }

        // DNS rebinding (TOCTOU) defence: for a resolvable hostname (not an IP literal, already checked
        // above), re-resolve immediately before the request and reject if any address is private.
        //
        // A destination the host named is exempt here as well as above, and it has to be: such a service is
        // reached at a private address by definition, so honouring the permission only in the validator
        // would let the URI pass and then refuse it here, one line before the request. There is no rebinding
        // to defend against either - the permission names the host, and an attacker who could change what it
        // resolves to already owns the name.
        if (options.Value.BlockPrivateNetworks &&
            !SecureUriValidator.IsAllowedDestination(uri, options.Value.AllowedDestinations) &&
            !IPAddress.TryParse(uri.Host, out _))
        {
            IPHostEntry hostEntry;
            try
            {
                hostEntry = await Dns.GetHostEntryAsync(uri.Host, cancellationToken);
            }
            catch (Exception ex)
            {
                throw new HttpRequestException(
                    $"SSRF protection: Unable to resolve hostname '{uri.Host}' immediately before request",
                    ex);
            }

            var privateAddress = hostEntry.AddressList.FirstOrDefault(SecureUriValidator.IsPrivateOrReservedAddress);
            if (privateAddress != null)
            {
                throw new HttpRequestException(
                    $"SSRF protection: DNS rebinding detected. Hostname '{uri.Host}' resolved to private/internal address {privateAddress} " +
                    $"immediately before HTTP request. This may indicate a DNS rebinding attack where the hostname resolved to " +
                    $"a public IP during initial validation but now resolves to a private IP.");
            }
        }

        // All checks passed, proceed with request
        return await base.SendAsync(request, cancellationToken);
    }
}
