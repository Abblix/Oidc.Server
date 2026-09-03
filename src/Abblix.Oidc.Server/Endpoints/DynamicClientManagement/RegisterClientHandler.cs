// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation of <see cref="IRegisterClientHandler"/> that runs validation
/// (RFC 7591 section 2 metadata + OIDC DCR 1.0) followed by processing (credential issuance,
/// persistence, and registration access token generation per RFC 7591 section 3.2.1 / RFC 7592 section 3).
/// </summary>
/// <param name="validator">Validator for the raw registration metadata.</param>
/// <param name="processor">Processor that persists the client and constructs the response.</param>
public class RegisterClientHandler(
    IRegisterClientRequestValidator validator,
    IRegisterClientRequestProcessor processor) : IRegisterClientHandler
{
    /// <summary>
    /// Validates the registration metadata, then provisions the client and returns the
    /// RFC 7591 section 3.2.1 success response or an error per section 3.2.2.
    /// </summary>
    /// <param name="clientRegistrationRequest">The client metadata payload.</param>
    public async Task<Result<ClientRegistrationSuccessResponse, OidcError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRegistrationRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
