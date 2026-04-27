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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the OpenID Connect RP-Initiated Logout 1.0 <c>post_logout_redirect_uris</c>:
/// each URI must be absolute, fragment-free, and consistent with the OIDC DCR 1.0 §2
/// scheme rules for the declared <c>application_type</c> (Web = <c>https</c>,
/// non-localhost; Native = custom scheme or <c>http://localhost</c>).
/// </summary>
public class PostLogoutRedirectUrisValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_redirect_uri</c> error on the first non-conforming entry,
    /// or <c>null</c> when every URI passes the rules above.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        foreach (var uri in request.PostLogoutRedirectUris)
        {
            if (uri is not { IsAbsoluteUri : true })
                return ErrorFactory.InvalidRedirectUri(
                    $"{Parameters.PostLogoutRedirectUris} must contain only absolute URIs");

            if (uri.Fragment.HasValue())
                return ErrorFactory.InvalidRedirectUri($"{Parameters.PostLogoutRedirectUris} must not contain fragment");

            var applicationType = context.Request.ApplicationType;
            switch (applicationType)
            {
                case ApplicationTypes.Web when uri.Scheme != Uri.UriSchemeHttps:
                    // Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris
                    return ErrorFactory.InvalidRedirectUri(
                            $"{Parameters.PostLogoutRedirectUris} must be secure ({Uri.UriSchemeHttps})");

                case ApplicationTypes.Web when IsLocalhost(uri):
                    // they MUST NOT use localhost as the hostname
                    return ErrorFactory.InvalidRedirectUri(
                            $"{Parameters.PostLogoutRedirectUris} must not use host name {uri.Host}");

                case ApplicationTypes.Web:
                    break;

                case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttp && !IsLocalhost(uri):
                    // Native Clients MUST only register redirect_uris using the http: scheme with localhost as the hostname
                    return ErrorFactory.InvalidRedirectUri(
                        $"Native Clients MUST only register {Parameters.PostLogoutRedirectUris} using the http: scheme with localhost as the hostname");

                case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttps:
                    // Native Clients MUST only register redirect_uris using custom URI schemes
                    return ErrorFactory.InvalidRedirectUri(
                        $"Native Clients MUST only register {Parameters.PostLogoutRedirectUris} using custom URI schemes");

                case ApplicationTypes.Native:
                    break;

                default:
                    throw new UnexpectedTypeException(nameof(applicationType), applicationType.GetType());
            }
        }

        return null;
    }

    private static bool IsLocalhost(Uri uri) => uri.IsLoopback || uri.Host == "localhost";
}
