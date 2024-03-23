// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    /// A <see cref="Task"/> that when completed will yield a <see cref="ClientRegistrationRequestValidationResult"/>,
    /// which may either indicate a successful validation through a <see cref="ValidClientRegistrationRequest"/>
    /// instance or detail any issues encountered during validation as a
    /// <see cref="ClientRegistrationRequestValidationResult"/>.
    /// </returns>
    /// <remarks>
    /// This method orchestrates the validation process by creating a validation context from the provided request
    /// and passing it to the context validator for evaluation. It ensures that only requests fulfilling all necessary
    /// conditions are considered valid, thus maintaining the integrity and security of the client registration process.
    /// </remarks>

    public async Task<ClientRegistrationRequestValidationResult> ValidateAsync(ClientRegistrationRequest request)
    {
        var context = new ClientRegistrationValidationContext(request);
        ClientRegistrationRequestValidationResult? error = await _validator.ValidateAsync(context);
        return error ?? new ValidClientRegistrationRequest(request, context.SectorIdentifier);
    }
}
