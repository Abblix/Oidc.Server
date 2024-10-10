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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the authentication method specified for the token endpoint in a client registration request.
/// This validator ensures that the provided authentication method is supported by the OpenID provider.
/// </summary>
public class TokenEndpointAuthMethodValidator: SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenEndpointAuthMethodValidator"/> class.
    /// This constructor injects the client authenticator service used for verifying supported authentication methods.
    /// </summary>
    /// <param name="clientAuthenticator">The client authenticator used to validate authentication methods.</param>
    public TokenEndpointAuthMethodValidator(IClientAuthenticator clientAuthenticator)
    {
        _clientAuthenticator = clientAuthenticator;
    }

    private readonly IClientAuthenticator _clientAuthenticator;

    /// <summary>
    /// Validates the token endpoint authentication method specified in the client registration request.
    /// This method checks if the provided authentication method is among those supported by the OpenID provider.
    /// </summary>
    /// <param name="context">The validation context containing client registration data.</param>
    /// <returns>
    /// A <see cref="ClientRegistrationValidationError"/> if the authentication method is not valid or supported,
    /// or null if the request is valid.
    /// </returns>
    protected override ClientRegistrationValidationError? Validate(ClientRegistrationValidationContext context)
    {
        var request = context.Request;

        // Check if the authentication method is specified and supported
        if (request.TokenEndpointAuthMethod.HasValue() &&
            !_clientAuthenticator.ClientAuthenticationMethodsSupported.Contains(
                request.TokenEndpointAuthMethod, StringComparer.Ordinal))
        {
            return new ClientRegistrationValidationError(
                ErrorCodes.InvalidRequest,
                $"The specified token endpoint authentication method '{request.TokenEndpointAuthMethod}' is not supported");
        }

        return null; // No errors; the request is valid
    }
}
