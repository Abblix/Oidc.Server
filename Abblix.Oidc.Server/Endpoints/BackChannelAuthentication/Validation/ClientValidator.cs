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
using Abblix.Oidc.Server.Features.ClientAuthentication;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the client in a backchannel authentication request, ensuring the client is registered
/// and authorized to perform the request as part of the authentication validation process.
/// </summary>
/// <param name="clientAuthenticator">The service used to authenticate and retrieve client information.</param>
public class ClientValidator(IClientAuthenticator clientAuthenticator) : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Validates the client in the context of a backchannel authentication request.
    /// Ensures that the client is recognized and authorized to make the request.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and client information.
    /// </param>
    /// <returns>
    /// A <see cref="OidcError"/> if the client is not valid,
    /// or null if the client is authorized.
    /// </returns>
    public async Task<OidcError?> ValidateAsync(
        BackChannelAuthenticationValidationContext context)
    {
        var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(context.ClientRequest);
        if (clientInfo == null)
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient, "The client is not authorized");
        }

        if (!clientInfo.AllowedGrantTypes.Contains(GrantTypes.Ciba))
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient, "The Client is not authorized to use this authentication flow");
        }

        if (string.IsNullOrEmpty(clientInfo.BackChannelTokenDeliveryMode))
        {
            return new OidcError(
                ErrorCodes.InvalidClient,
                "The client is not properly configured for backchannel authentication. " +
                "A token delivery mode (poll, ping, or push) must be specified.");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
