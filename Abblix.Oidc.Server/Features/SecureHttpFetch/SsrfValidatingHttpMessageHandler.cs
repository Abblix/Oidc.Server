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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// HTTP message handler that prevents SSRF attacks by re-validating DNS resolution immediately before making HTTP requests.
/// This handler provides defense against DNS rebinding attacks (TOCTOU - Time-Of-Check-Time-Of-Use vulnerability)
/// where an attacker controls DNS and changes resolution between validation and HTTP request.
/// </summary>
/// <remarks>
/// Attack scenario prevented:
/// 1. Initial validation: evil.com resolves to 8.8.8.8 (public IP, passes validation)
/// 2. DNS TTL expires (low TTL like 1 second)
/// 3. Attacker changes DNS: evil.com now resolves to 127.0.0.1
/// 4. HTTP request: Without this handler, request would go to localhost
/// 5. With this handler: DNS is re-validated, private IP detected, request blocked
///
/// This handler is used as part of a defense-in-depth strategy alongside SsrfHttpFetchValidator.
/// </remarks>
public class SsrfValidatingHttpMessageHandler : DelegatingHandler
{
    /// <summary>
    /// Sends HTTP request with immediate pre-request DNS validation to prevent TOCTOU attacks.
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

        // Re-validate DNS immediately before sending request to prevent DNS rebinding
        var hostname = uri.Host;

        // Skip validation for IP addresses (already validated by SsrfHttpFetchValidator)
        if (IPAddress.TryParse(hostname, out _))
        {
            return await base.SendAsync(request, cancellationToken);
        }

        // Resolve DNS and check all resolved addresses
        IPHostEntry hostEntry;
        try
        {
            hostEntry = await Dns.GetHostEntryAsync(hostname, cancellationToken);
        }
        catch (Exception ex)
        {
            throw new HttpRequestException(
                $"SSRF protection: Unable to resolve hostname '{hostname}' immediately before request",
                ex);
        }

        // Check if any resolved address is private/reserved
        var privateAddress = hostEntry.AddressList.FirstOrDefault(IsPrivateOrReservedAddress);
        if (privateAddress != null)
        {
            throw new HttpRequestException(
                $"SSRF protection: DNS rebinding detected. Hostname '{hostname}' resolved to private/internal address {privateAddress} " +
                $"immediately before HTTP request. This may indicate a DNS rebinding attack where the hostname resolved to " +
                $"a public IP during initial validation but now resolves to a private IP.");
        }

        // All checks passed, proceed with request
        return await base.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// Checks if an IP address is private, loopback, link-local, or otherwise reserved.
    /// This is a duplicate of the method in SsrfHttpFetchValidator to avoid tight coupling.
    /// </summary>
    private static bool IsPrivateOrReservedAddress(IPAddress address)
    {
        // Loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
        if (IPAddress.IsLoopback(address))
            return true;

        var bytes = address.GetAddressBytes();

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork =>
                // Private: 10.0.0.0/8
                bytes[0] == 10 ||
                // Private: 172.16.0.0/12
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                // Private: 192.168.0.0/16
                (bytes[0] == 192 && bytes[1] == 168) ||
                // Link-local: 169.254.0.0/16 (AWS/Azure metadata)
                (bytes[0] == 169 && bytes[1] == 254) ||
                // Multicast: 224.0.0.0/4
                bytes[0] >= 224,

            AddressFamily.InterNetworkV6 =>
                // Link-local: fe80::/10
                (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) ||
                // Unique local: fc00::/7
                (bytes[0] & 0xfe) == 0xfc ||
                // Multicast: ff00::/8
                bytes[0] == 0xff,

            _ => true,
        };
    }
}
