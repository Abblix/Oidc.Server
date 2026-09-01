// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates that a registered <c>jwks_uri</c> names a destination this deployment is allowed to fetch
/// from: RFC 7591 Section 2 makes the member a URL, and this server fetches it to load the client's keys.
/// </summary>
/// <remarks>
/// A value the fetch cannot resolve registers happily and produces a client whose keys can never be
/// loaded. What the registrant then meets is a <c>private_key_jwt</c> assertion refused as "no signing
/// key matched", at a moment that names neither the metadata nor the mistake - and nothing upstream can
/// say more, since the fetcher answers every failure with an empty key set. Registration is the last
/// point at which the caller is still on the line to be told.
/// <para>
/// Absoluteness is asked HERE and everything else is asked of the POLICY, which is what
/// <see cref="BackChannelLogoutUriValidator"/> does with the other address this server fetches. The
/// split matters because absoluteness alone is not the property: a dot is legal in a URI scheme, so
/// <c>client.example.com:8080/jwks</c> - the way people write a host and a port - parses as an ABSOLUTE
/// URI whose scheme is the host name and whose <see cref="Uri.Host"/> is empty, and every member the
/// policy reads below would then be read off a value that names nowhere.
/// </para>
/// <para>
/// The scheme is NOT decided here, and a literal <c>https</c> would be wrong: <see cref="SecureHttpFetchOptions.AllowedDestinations"/>
/// names an address the deployment reaches inside its own network, over plain HTTP, and the policy lifts
/// the scheme restriction for exactly those. Refusing them at registration while the fetch allows them
/// would make one fetched endpoint disagree with the other about the same address.
/// </para>
/// </remarks>
/// <param name="uriValidator">The shared SSRF URI policy used by the outbound HTTP handler.</param>
public class JwksUriValidator(ISecureUriValidator uriValidator) : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when <c>jwks_uri</c> is relative or violates the
    /// fetch policy; <c>null</c> when it is absent or compliant.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var uri = context.Request.JwksUri;
        if (uri is null)
            return null;

        if (!uri.IsAbsoluteUri)
            return ErrorFactory.InvalidClientMetadata($"The {Parameters.JwksUri} is not an absolute URI");

        var rejection = uriValidator.Validate(uri);
        if (rejection != null)
            return ErrorFactory.InvalidClientMetadata($"The {Parameters.JwksUri} is not allowed: {rejection}");

        return null;
    }
}
