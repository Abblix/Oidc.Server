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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the client information in the context of a token request, ensuring that the client is properly authenticated.
/// </summary>
/// <remarks>
/// This validator is responsible for authenticating the client making the token request. It leverages the
/// <see cref="IClientAuthenticator"/> to perform the authentication, and if successful, attaches the client information
/// to the validation context. If the authentication fails, it returns an error indicating that the client is not authorized.
/// </remarks>
public class ClientValidator: ITokenContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientValidator"/> class with the specified client authenticator.
    /// </summary>
    /// <param name="clientAuthenticator">The client authenticator used to authenticate the client.</param>
    public ClientValidator(IClientAuthenticator clientAuthenticator)
    {
        _clientAuthenticator = clientAuthenticator;
    }

    private readonly IClientAuthenticator _clientAuthenticator;

    /// <summary>
    /// Asynchronously validates the client in the token request context. This method checks if the client
    /// can be authenticated using the provided client request information. If the client is successfully authenticated,
    /// the client information is added to the context; otherwise, an error is returned.
    /// </summary>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="TokenRequestError"/> if the client cannot be authenticated,
    /// otherwise null indicating successful validation.
    /// </returns>
    public async Task<TokenRequestError?> ValidateAsync(TokenValidationContext context)
    {
        var clientRequest = context.ClientRequest;
        var clientInfo = await _clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
        if (clientInfo == null)
        {
            return new TokenRequestError(ErrorCodes.InvalidClient, "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
