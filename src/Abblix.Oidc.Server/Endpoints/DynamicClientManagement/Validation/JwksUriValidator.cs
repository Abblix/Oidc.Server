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
/// Validates that a registered <c>jwks_uri</c> is an absolute https URL: RFC 7591 Section 2 makes the
/// member a URL, and this server fetches it to load the client's keys.
/// </summary>
/// <remarks>
/// A value the fetch cannot resolve registers happily and produces a client whose keys can never be
/// loaded. What the registrant then meets is a <c>private_key_jwt</c> assertion refused as "no signing
/// key matched", at a moment that names neither the metadata nor the mistake - and nothing upstream can
/// say more, since the fetcher answers every failure with an empty key set. Registration is the last
/// point at which the caller is still on the line to be told.
/// <para>
/// BOTH halves, because absoluteness alone is not the property. A dot is legal in a URI scheme, so
/// <c>client.example.com:8080/jwks</c> - the way people write a host and a port - parses as an ABSOLUTE
/// URI whose scheme is the host name and whose <see cref="Uri.Host"/> is empty. It names no destination
/// and it is the mistake a registrant actually makes, so a check that reads only
/// <see cref="Uri.IsAbsoluteUri"/> admits exactly the value this validator exists to refuse.
/// </para>
/// <para>
/// The scheme is decided here rather than left to the fetch because it is a fact about the TEXT: it
/// needs no name resolution and cannot go stale, unlike the loopback and private-network verdicts, which
/// belong to <c>SsrfValidatingHttpMessageHandler</c> and are taken against an address re-resolved
/// immediately before the request.
/// </para>
/// </remarks>
public class JwksUriValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when <c>jwks_uri</c> is relative or is not https;
    /// <c>null</c> when it is absent or an absolute https URL.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var uri = context.Request.JwksUri;
        if (uri is null || uri is { IsAbsoluteUri: true, Scheme: "https" })
            return null;

        return ErrorFactory.InvalidClientMetadata(
            $"The {Parameters.JwksUri} must be an absolute https URI");
    }
}
