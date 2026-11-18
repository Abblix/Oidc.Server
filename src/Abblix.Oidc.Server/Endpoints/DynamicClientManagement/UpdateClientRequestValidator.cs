// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Validates an RFC 7592 section 2.2 update request: authenticates the registration access token and
/// confirms the client exists, then runs the supplied replacement metadata through the
/// <see cref="IClientRegistrationContextValidator"/> pipeline as an update of the registration the token was
/// authenticated against. Also enforces the RFC 7592 section 2.2 rule that the request body's <c>client_id</c> must
/// match the authenticated client.
/// </summary>
/// <remarks>
/// The pipeline judges the very registration the update is then built from and written over, so a change the host
/// makes to the client meanwhile cannot have the update judged under one security profile and stored under another.
/// </remarks>
/// <param name="clientRequestValidator">Validator for the registration access token.</param>
/// <param name="registrationValidator">The metadata validation pipeline registration and update share.</param>
public class UpdateClientRequestValidator(
    IClientRequestValidator clientRequestValidator,
    IClientRegistrationContextValidator registrationValidator)
    : IUpdateClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidUpdateClientRequest, OidcError>> ValidateAsync(TenantDefinition tenant, UpdateClientRequest request)
    {
        // First validate client authentication (registration_access_token)
        var clientValidation = await clientRequestValidator.ValidateAsync(tenant, request.ClientRequest);
        var validClientRequest = clientValidation;

        if (validClientRequest.TryGetFailure(out var clientError))
            return clientError;

        var clientInfo = validClientRequest.GetSuccess();

        // RFC 7592 Section 2.2: client_id in request body must match authenticated client. The section names no code of
        // its own and sends an invalid field to the RFC 7591 section 3.2.2 errors, which name none for the request as such
        if (request.RegistrationRequest.ClientId != clientInfo.Client.ClientInfo.ClientId)
        {
            return new OidcError(
                ErrorCodes.InvalidClientMetadata,
                "The client_id in the request body must match the authenticated client");
        }

        var context = new ClientRegistrationValidationContext(request.RegistrationRequest)
        {
            Operation = DynamicClientOperation.Update,
            StoredClient = clientInfo.Client.ClientInfo,
        };

        var error = await registrationValidator.ValidateAsync(tenant, context);
        if (error != null)
            return error;

        // The pairwise subjects every end user of the client already holds are computed under its sector, so an
        // update deriving another sector would hand each of them a new identity; it is refused instead
        if (!string.Equals(context.SectorIdentifier, clientInfo.Client.ClientInfo.SectorIdentifier, StringComparison.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidClientMetadata,
                "The subject type and the sector of a registered client cannot change, since its end users would be given new " +
                "identifiers; a client that needs others registers anew");
        }

        return new ValidUpdateClientRequest(request, clientInfo.Client, context.Request);
    }
}
