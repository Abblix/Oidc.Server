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
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the client in a backchannel authentication request, ensuring the client is registered
/// and authorized to perform the request as part of the authentication validation process.
/// </summary>
/// <param name="clientAuthenticator">The service used to authenticate and retrieve client information.</param>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class ClientValidator(IClientAuthenticator clientAuthenticator, ITenantAccessor tenantAccessor)
    : IBackChannelAuthenticationContextValidator
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
        var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(
            tenantAccessor.CurrentTenant(), context.ClientRequest);
        if (clientInfo == null)
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient, "The client is not authorized");
        }

        // CIBA Core 1.0 section 7.1: "The Client MUST authenticate to the Backchannel Authentication Endpoint". A
        // client registered with the method "none" authenticates nobody, so the flow is not open to it.
        if (!clientInfo.EffectiveGrantTypes.Contains(GrantTypes.Ciba) || clientInfo is { ClientType: ClientType.Public })
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
