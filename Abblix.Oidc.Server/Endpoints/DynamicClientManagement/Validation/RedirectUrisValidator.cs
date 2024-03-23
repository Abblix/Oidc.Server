// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This internal class validates Redirect URIs in a client registration request. It checks if the URIs are absolute,
/// do not contain fragments, and comply with security requirements based on the application type.
/// If any validation fails, it returns a ClientRegistrationValidationError.
/// </summary>
internal class RedirectUrisValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates Redirect URIs in the client registration request.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A ClientRegistrationValidationError if any validation fails, or null if the request is valid.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.RedirectUris.Length == 0)
            return ErrorFactory.InvalidRedirectUri($"{Parameters.RedirectUris} is required");

        foreach (var uri in request.RedirectUris)
        {
            if (uri is not { IsAbsoluteUri : true })
                return ErrorFactory.InvalidRedirectUri($"{Parameters.RedirectUris} must contain only absolute URIs");

            if (uri.Fragment.HasValue())
                return ErrorFactory.InvalidRedirectUri($"{Parameters.RedirectUris} must not contain fragment");

            var applicationType = context.Request.ApplicationType;
            switch (applicationType)
            {
                case ApplicationTypes.Web when uri.Scheme != Uri.UriSchemeHttps:
                    // Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris
                    return ErrorFactory.InvalidRedirectUri(
                        $"{Parameters.RedirectUris} must be secure ({Uri.UriSchemeHttps})");

                case ApplicationTypes.Web when IsLocalhost(uri):
                    // they MUST NOT use localhost as the hostname
                    return ErrorFactory.InvalidRedirectUri(
                        $"{Parameters.RedirectUris} must not use host name {uri.Host}");

                case ApplicationTypes.Web:
                    break;

                case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttp && !IsLocalhost(uri):
                    // Native Clients MUST only register redirect_uris using the http: scheme with localhost as the hostname
                    return ErrorFactory.InvalidRedirectUri(
                        $"Native Clients MUST only register {Parameters.RedirectUris} using the http: scheme with localhost as the hostname");

                case ApplicationTypes.Native when uri.Scheme == Uri.UriSchemeHttps:
                    // Native Clients MUST only register redirect_uris using custom URI schemes
                    return ErrorFactory.InvalidRedirectUri(
                        $"Native Clients MUST only register {Parameters.RedirectUris} using custom URI schemes");

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
