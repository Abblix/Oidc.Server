// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
