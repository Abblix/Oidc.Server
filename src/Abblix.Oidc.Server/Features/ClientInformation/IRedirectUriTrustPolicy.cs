// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Decides whether the authorization endpoint may send the user agent to a client's registered redirect URIs on its
/// own, with an error the end user did not choose.
/// </summary>
/// <remarks>
/// RFC 9700 section 4.11.2: whoever registers a client registers its redirect URI too, and an erroneous request, a
/// declined consent or a silent request (<c>prompt=none</c>) would then have the server redirect the user agent there.
/// "Based on its risk assessment, the authorization server needs to decide whether or not it can trust the redirection
/// URI", and it "SHOULD only automatically redirect the user agent if it trusts the redirection URI". An authorization
/// error for a client this policy does not trust is answered by the server itself, with status 400 and the error in
/// the body, rather than at the client's redirect URI; a successful authorization still reaches the client, since it
/// follows the end user's own consent to that client.
/// <para>
/// The default, <see cref="RedirectUriTrustPolicy"/>, trusts every client but one nobody reviewed. A host registering
/// its own implementation decides by its own assessment, the source of the client or what is known of its URIs.
/// </para>
/// </remarks>
public interface IRedirectUriTrustPolicy
{
    /// <summary>
    /// Whether the server may redirect the user agent to the redirect URIs of <paramref name="client"/> with an
    /// authorization error.
    /// </summary>
    /// <param name="tenant">The tenant the authorization request is served at.</param>
    /// <param name="client">The client the request names, found at that tenant.</param>
    /// <returns><c>true</c> when the client's redirect URIs are trusted.</returns>
    Task<bool> IsTrustedAsync(TenantDefinition tenant, ClientInfo client);
}
