// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates that a registered <c>jwks_uri</c> names a destination: RFC 7591 Section 2 makes the member a
/// URL, and this server fetches it to load the client's keys.
/// </summary>
/// <remarks>
/// A relative value registers today and produces a client whose keys can never be loaded, because the
/// fetch cannot resolve it. What the registrant then meets is a <c>private_key_jwt</c> assertion refused
/// as "no signing key matched", at a moment that names neither the metadata nor the mistake - and nothing
/// upstream can say more, since an HTTP client with no base address refuses a relative request URI before
/// the outbound policy handler is entered, and the fetcher answers any failure with an empty key set.
/// Registration is the last point at which the caller is still on the line to be told.
/// <para>
/// Absoluteness only. The SSRF policy over the same address belongs to the fetch and is applied there by
/// <c>SsrfValidatingHttpMessageHandler</c>, which re-resolves DNS immediately before the request - a
/// verdict taken at registration would be a verdict about a name whose address may since have changed.
/// </para>
/// </remarks>
public class JwksUriValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when <c>jwks_uri</c> is relative; <c>null</c> when
    /// it is absent or absolute.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var uri = context.Request.JwksUri;
        if (uri is null || uri.IsAbsoluteUri)
            return null;

        return ErrorFactory.InvalidClientMetadata($"The {Parameters.JwksUri} is not an absolute URI");
    }
}
