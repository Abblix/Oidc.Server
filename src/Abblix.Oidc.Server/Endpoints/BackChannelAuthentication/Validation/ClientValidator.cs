// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates that the client which authenticated a backchannel authentication request is authorized to use the
/// flow. The client is authenticated once, by the handler, before its request object is read.
/// </summary>
public class ClientValidator : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Checks that the authenticated client is open to the backchannel authentication flow.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and the authenticated client.
    /// </param>
    /// <returns>
    /// A <see cref="OidcError"/> if the client is not authorized to use the flow,
    /// or null if it is.
    /// </returns>
    public Task<OidcError?> ValidateAsync(
        TenantDefinition tenant,
        BackChannelAuthenticationValidationContext context)
        => Task.FromResult(WhyRefused(context.ClientInfo));

    private static OidcError? WhyRefused(ClientInfo clientInfo)
    {
        // CIBA Core 1.0 section 7.1: "The Client MUST authenticate to the Backchannel Authentication Endpoint". A
        // client registered with the method "none" authenticates nobody, so the flow is not open to it.
        if (!clientInfo.EffectiveGrantTypes.Contains(GrantTypes.Ciba) || clientInfo is { ClientType: ClientType.Public })
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient, "The Client is not authorized to use this authentication flow");
        }

        if (string.IsNullOrEmpty(clientInfo.BackChannelTokenDeliveryMode))
        {
            // The client has authenticated, so this is not invalid_client (a 401 challenging credentials that
            // worked): CIBA Core 1.0 section 13, unauthorized_client, "The Client is not authorized to use this
            // authentication flow".
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not properly configured for backchannel authentication. " +
                "A token delivery mode (poll, ping, or push) must be specified.");
        }

        return null;
    }
}
