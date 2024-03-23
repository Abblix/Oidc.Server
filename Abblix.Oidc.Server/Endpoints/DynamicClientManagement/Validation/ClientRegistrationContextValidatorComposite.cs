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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This class represents a composite validator for client registration requests.
/// It aggregates multiple validation steps and executes them sequentially.
/// </summary>
public class ClientRegistrationContextValidatorComposite : IClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the class with an array of validation steps.
    /// </summary>
    /// <param name="validationSteps">The array of validation steps to be executed.</param>
    public ClientRegistrationContextValidatorComposite(IClientRegistrationContextValidator[] validationSteps)
    {
        _validationSteps = validationSteps;
    }

    private readonly IClientRegistrationContextValidator[] _validationSteps;

    /// <summary>
    /// Validates the client registration request by executing each validation step in the specified order.
    /// </summary>
    /// <param name="context">The validation context containing client registration information.</param>
    /// <returns>A ClientRegistrationValidationError if any validation step fails, or null if the request is valid.</returns>
    public async Task<ClientRegistrationValidationError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        foreach (var validationStep in _validationSteps)
        {
            var error = await validationStep.ValidateAsync(context);
            if (error != null)
                return error;
        }

        return null;
    }
}
