// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
