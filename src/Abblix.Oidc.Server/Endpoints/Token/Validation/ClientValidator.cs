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

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the client information in the context of a token request, ensuring that the client is properly authenticated.
/// </summary>
/// <remarks>
/// This validator is responsible for authenticating the client making the token request. It leverages the
/// <see cref="IClientAuthenticator"/> to perform the authentication, and if successful, attaches the client information
/// to the validation context. If the authentication fails, it returns an error indicating that the client is not authorized.
/// </remarks>
/// <param name="clientAuthenticator">The client authenticator used to authenticate the client.</param>
public class ClientValidator(IClientAuthenticator clientAuthenticator): ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the client in the token request context. This method checks if the client
    /// can be authenticated using the provided client request information. If the client is successfully authenticated,
    /// the client information is added to the context; otherwise, an error is returned.
    /// </summary>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the client cannot be authenticated,
    /// otherwise null indicating successful validation.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        var clientRequest = context.ClientRequest;
        var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
        if (clientInfo == null)
        {
            return new OidcError(ErrorCodes.InvalidClient, "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
