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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Applies the synchronous portion of the SSRF policy (scheme allow-list, internal-hostname and
/// private/reserved IP-literal blocking) configured by <see cref="SecureHttpFetchOptions"/> to a URI.
/// Used both by the outbound HTTP handler immediately before a request and at registration time to
/// reject client-supplied URIs the server would later fetch (e.g. a back-channel logout endpoint).
/// </summary>
/// <remarks>
/// This check is deliberately DNS-free: resolving a hostname is a runtime concern (and a registration
/// would otherwise fail for a client whose endpoint is not yet deployed). The outbound handler still
/// re-resolves and re-validates addresses immediately before each request to defeat DNS rebinding.
/// </remarks>
public interface ISecureUriValidator
{
    /// <summary>
    /// Validates a URI against the configured SSRF policy without resolving DNS.
    /// </summary>
    /// <param name="uri">The URI to validate.</param>
    /// <returns><c>null</c> when the URI is allowed; otherwise a human-readable reason for the rejection.</returns>
    string? Validate(Uri uri);
}
