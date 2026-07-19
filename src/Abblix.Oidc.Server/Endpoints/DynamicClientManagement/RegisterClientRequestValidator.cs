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
/// Default validator for new-client registration (POST), wrapping the request in a
/// <see cref="ClientRegistrationValidationContext"/> with
/// <see cref="DynamicClientOperation.Register"/> and delegating to the configured
/// <see cref="IClientRegistrationContextValidator"/> pipeline.
/// </summary>
/// <param name="validator">Composite validator that runs the individual metadata checks.</param>
public class RegisterClientRequestValidator(IClientRegistrationContextValidator validator) : IRegisterClientRequestValidator
{
    /// <summary>
    /// Runs the validator pipeline and, on success, returns the typed valid request together
    /// with the resolved sector identifier.
    /// </summary>
    /// <param name="request">The raw registration request.</param>
    public async Task<Result<ValidClientRegistrationRequest, OidcError>> ValidateAsync(ClientRegistrationRequest request)
    {
        var context = new ClientRegistrationValidationContext(request);
        var error = await validator.ValidateAsync(context);
        if (error != null)
        {
            return error;
        }

        return new ValidClientRegistrationRequest(request, context.SectorIdentifier);
    }
}
