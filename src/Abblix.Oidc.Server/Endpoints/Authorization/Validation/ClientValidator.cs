// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.MultiTenancy;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the client specified in the authorization request.
/// This class checks whether the client is registered and authorized to perform the request,
/// as part of the authorization validation process. It plays a crucial role in ensuring that
/// only valid and authorized clients can initiate authorization requests.
/// </summary>
/// <param name="logger">The logger to be used for recording validation activities and outcomes.</param>
/// <param name="clientInfoProvider">The provider used to retrieve information about clients.</param>
/// <param name="clientKeysProvider">Supplies the encryption keys the client publishes, judged against its profile.
/// </param>
/// <param name="options">Supplies the service token settings the client's access and refresh tokens are issued with.
/// </param>
public partial class ClientValidator(
    ILogger<ClientValidator> logger,
    IClientInfoProvider clientInfoProvider,
    IClientKeysProvider clientKeysProvider,
    IOptions<OidcOptions> options) : IAuthorizationContextValidator
{
    /// <summary>
    /// Asynchronously validates the client specified in the authorization request.
    /// Ensures the client is recognized and authorized to make the request.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">
    /// The validation context containing details of the authorization request and client information.
    /// </param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the client is not found or not authorized,
    /// or null if the client is valid.
    /// </returns>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(TenantDefinition tenant, AuthorizationValidationContext context)
    {
        var clientId = context.Request.ClientId;
        if (clientId is null)
        {
            return context.Error(ErrorCodes.UnauthorizedClient, "The client id is required");
        }

        var clientInfo = await clientInfoProvider.TryFindClientAsync(tenant, clientId);
        if (clientInfo == null)
        {
            LogClientNotFound(clientId);
            return context.Error(ErrorCodes.UnauthorizedClient, "The client is not authorized");
        }

        // FAPI 1.0 Part 2 section 8.6, FAPI 2.0 section 5.4.1: the server signs only with the profile's algorithms,
        // and this endpoint signs for the client with what the client is configured for - a front-channel ID token,
        // a JWT authorization response. A client the startup check never saw, added to the store afterwards, is
        // refused here before anything is signed for it
        // So are the access and refresh tokens it would be issued, signed and encrypted with what the deployment
        // configures, and the key set it publishes, where its profile leaves nothing in it to encrypt to
        var requirements = SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile);
        IReadOnlyList<string> violations =
        [
            ..SecurityProfileConsistency.FindAlgorithmViolations(clientInfo, requirements),
            ..SecurityProfileConsistency.FindServiceTokenViolations(
                SecurityProfileConsistency.IssuedToAClient(options.Value.ServiceTokens), requirements),
            ..await SecurityProfileConsistency.FindEncryptionKeyViolationsAsync(
                clientKeysProvider, clientInfo, requirements),
        ];
        if (violations.Count > 0)
        {
            LogClientCannotSatisfyProfile(clientId, violations);
            return context.Error(
                ErrorCodes.UnauthorizedClient, "The client's configuration does not satisfy its security profile");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
