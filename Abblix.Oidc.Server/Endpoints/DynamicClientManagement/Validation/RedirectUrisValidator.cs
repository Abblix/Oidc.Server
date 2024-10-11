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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates Redirect URIs in a client registration request.
/// This internal class checks if the URIs are absolute, do not contain fragments,
/// and comply with security requirements based on the application type.
/// If any validation fails, it returns a ClientRegistrationValidationError.
/// </summary>
internal class RedirectUrisValidator : SyncClientRegistrationContextValidator
{
    private static readonly string[] RequiringRedirectUri = {
        GrantTypes.AuthorizationCode,
        GrantTypes.Implicit,
        GrantTypes.RefreshToken,
    };

    /// <summary>
    /// Validates Redirect URIs in the client registration request.
    /// This method ensures that the registered Redirect URIs meet the necessary criteria
    /// required by the OAuth 2.0 and OpenID Connect specifications.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A <see cref="ClientRegistrationValidationError"/> if any validation fails,
    /// or null if the request is valid.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.GrantTypes.Intersect(RequiringRedirectUri, StringComparer.Ordinal).Any())
        {
            if (request.RedirectUris.Length == 0)
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
        => uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.Ordinal);
}
