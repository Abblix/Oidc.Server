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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Validates update client requests by checking authentication and ensuring client exists per RFC 7592.
/// </summary>
/// <param name="clientRequestValidator">Validator for client authentication via registration_access_token.</param>
/// <param name="registrationRequestValidator">Validator for client registration metadata (keyed service).</param>
public class UpdateClientRequestValidator(
    IClientRequestValidator clientRequestValidator,
    [FromKeyedServices(UpdateClientRequestValidator.RegistrationKey)] IRegisterClientRequestValidator registrationRequestValidator) : IUpdateClientRequestValidator
{
    /// <summary>
    /// Service key for the update-specific registration validator.
    /// </summary>
    public const string RegistrationKey = nameof(UpdateClientRequestValidator);

    /// <summary>
    /// Validates an update client request asynchronously per RFC 7592 Section 2.2.
    /// </summary>
    /// <param name="request">The update request to validate.</param>
    /// <returns>A task that returns the validation result.</returns>
    public async Task<Result<ValidUpdateClientRequest, OidcError>> ValidateAsync(UpdateClientRequest request)
    {
        // First validate client authentication (registration_access_token)
        var clientValidation = await clientRequestValidator.ValidateAsync(request.ClientRequest);
        if (clientValidation.TryGetFailure(out var clientError))
            return clientError;

        if (!clientValidation.TryGetSuccess(out var validClientRequest))
            return new OidcError(ErrorCodes.ServerError, "Unexpected validation state");

        // RFC 7592 Section 2.2: client_id in request body must match authenticated client
        if (request.RegistrationRequest.ClientId != validClientRequest.ClientInfo.ClientId)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The client_id in the request body must match the authenticated client");
        }

        // Validate the registration request metadata using update-specific validator
        var registrationValidation = await registrationRequestValidator.ValidateAsync(request.RegistrationRequest);
        if (registrationValidation.TryGetFailure(out var registrationError))
            return registrationError;

        if (!registrationValidation.TryGetSuccess(out var validRegistration))
            return new OidcError(ErrorCodes.ServerError, "Unexpected validation state");

        return new ValidUpdateClientRequest(
            request,
            validClientRequest.ClientInfo,
            validRegistration.Model);
    }
}
