// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates that the requested <c>token_endpoint_auth_method</c> (RFC 7591 section 2) is one this
/// server announces in <c>token_endpoint_auth_methods_supported</c> on its discovery document.
/// </summary>
/// <param name="clientAuthenticator">Source of supported client authentication methods.</param>
public class TokenEndpointAuthMethodValidator(IClientAuthenticator clientAuthenticator) : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Validates the token endpoint authentication method specified in the client registration request.
    /// This method checks if the provided authentication method is among those supported by the OpenID provider.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the authentication method is not valid or supported,
    /// or null if the request is valid.
    /// </returns>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        if (request.TokenEndpointAuthMethod.HasValue() &&
            !clientAuthenticator.ClientAuthenticationMethodsSupported.Contains(
                request.TokenEndpointAuthMethod, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"The specified token endpoint authentication method '{request.TokenEndpointAuthMethod}' is not supported");
        }

        return null;
    }
}
