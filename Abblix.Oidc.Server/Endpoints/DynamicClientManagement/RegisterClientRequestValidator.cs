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

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Provides validation for client registration requests to ensure they meet the system's criteria for client
/// registrations. Utilizes an underlying context validator for comprehensive evaluation of request parameters.
/// </summary>
public class RegisterClientRequestValidator : IRegisterClientRequestValidator
{
    /// <summary>
    /// Instantiates a new <see cref="RegisterClientRequestValidator"/> with a specific context validator for
    /// evaluating client registration requests.
    /// </summary>
    /// <param name="validator">An implementation of <see cref="IClientRegistrationContextValidator"/> used to assess
    /// the validity of registration requests based on predefined criteria and the system's registration policies.
    /// </param>
    public RegisterClientRequestValidator(IClientRegistrationContextValidator validator)
    {
        _validator = validator;
    }

    private readonly IClientRegistrationContextValidator _validator;

    /// <summary>
    /// Asynchronously validates a client registration request against the system's registration policies and criteria.
    /// </summary>
    /// <param name="request">The <see cref="ClientRegistrationRequest"/> containing the details of the client seeking
    /// registration.</param>
    /// <returns>
    /// A <see cref="Task"/> that when completed will yield a <see cref="Result<ValidClientRegistrationRequest, RequestError>"/>,
    /// which may either indicate a successful validation through a <see cref="ValidClientRegistrationRequest"/>
    /// instance or detail any issues encountered during validation as a
    /// <see cref="Result<ValidClientRegistrationRequest, RequestError>"/>.
    /// </returns>
    /// <remarks>
    /// This method orchestrates the validation process by creating a validation context from the provided request
    /// and passing it to the context validator for evaluation. It ensures that only requests fulfilling all necessary
    /// conditions are considered valid, thus maintaining the integrity and security of the client registration process.
    /// </remarks>

    public async Task<Result<ValidClientRegistrationRequest, RequestError>> ValidateAsync(ClientRegistrationRequest request)
    {
        var context = new ClientRegistrationValidationContext(request);
        Result<ValidClientRegistrationRequest, RequestError>? error = await _validator.ValidateAsync(context);
        return error ?? new ValidClientRegistrationRequest(request, context.SectorIdentifier);
    }
}
