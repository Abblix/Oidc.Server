// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates <c>redirect_uris</c> in a registration request per RFC 7591 §2 and the
/// per-application-type rules of OIDC DCR 1.0 §2: required when the client uses
/// <c>authorization_code</c>, <c>implicit</c>, or <c>refresh_token</c>; absolute and
/// fragment-free; Web clients use <c>https</c> and not localhost; Native clients use
/// a custom scheme or <c>http://localhost</c>.
/// </summary>
internal class RedirectUrisValidator : SyncClientRegistrationContextValidator
{
    private static readonly string[] RequiringRedirectUri =
    [
        GrantTypes.AuthorizationCode,
        GrantTypes.Implicit,
        GrantTypes.RefreshToken
    ];

    /// <summary>
    /// Returns an <c>invalid_redirect_uri</c> error on the first non-conforming entry,
    /// or <c>null</c> when every URI passes.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.GrantTypes.Intersect(RequiringRedirectUri, StringComparer.Ordinal).Any())
        {
            // Absent, explicitly null, and empty are one answer: the client registered no redirect URI for
            // a grant type that cannot deliver a response without one. The property is declared
            // non-nullable, but a registration body is attacker-shaped JSON and the deserializer honours
            // neither the annotation nor a member initialiser against an explicit null, so the null is
            // real, and reading Length on it turned a rejected registration into an unhandled exception.
            // The error code is the one this validator already returns for the empty case: RFC 7591
            // section 3.2.2 defines invalid_redirect_uri as "The value of one or more redirection URIs is
            // invalid", which names bad values rather than absent ones, so answering absence with it is
            // this library's choice and not something the document requires.
            if (request.RedirectUris is not { Length: > 0 })
                return ErrorFactory.InvalidRedirectUri($"{Parameters.RedirectUris} is required");

            foreach (var uri in request.RedirectUris)
            {
                if (uri is not { IsAbsoluteUri: true })
                    return ErrorFactory.InvalidRedirectUri(
                        $"{Parameters.RedirectUris} must contain only absolute URIs");

                if (uri.Fragment.HasValue())
                    return ErrorFactory.InvalidRedirectUri($"{Parameters.RedirectUris} must not contain fragment");

                var applicationType = context.Request.ApplicationType;
                switch (applicationType)
                {
                    // Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris
                    case ApplicationTypes.Web when uri.Scheme != Uri.UriSchemeHttps:
                        return ErrorFactory.InvalidRedirectUri(
                            $"{Parameters.RedirectUris} must be secure ({Uri.UriSchemeHttps})");

                    // Web Clients MUST NOT use localhost as the hostname
                    case ApplicationTypes.Web when IsLocalhost(uri):
                        return ErrorFactory.InvalidRedirectUri(
                            $"{Parameters.RedirectUris} must not use host name {uri.Host}");

                    // Native Clients MUST only register redirect_uris using the http: scheme with localhost as the hostname
                    case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttp && !IsLocalhost(uri):
                        return ErrorFactory.InvalidRedirectUri(
                            $"Native Clients MUST only register {Parameters.RedirectUris} using the http: scheme with localhost as the hostname");

                    // Native Clients MUST only register redirect_uris using custom URI schemes
                    case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttps:
                        return ErrorFactory.InvalidRedirectUri(
                            $"Native Clients MUST only register {Parameters.RedirectUris} using custom URI schemes");

                    // Any other case of Web or Native application types is correct
                    case ApplicationTypes.Web:
                    case ApplicationTypes.Native:
                        break;

                    default:
                        throw new UnexpectedTypeException(nameof(applicationType), applicationType.GetType());
                }
            }
        }

        return null; // All validations passed successfully
    }

    // Helper method to determine if the provided URI uses localhost or loopback address
    private static bool IsLocalhost(Uri uri)
        => uri.IsLoopback || uri.Host == "localhost";
}
