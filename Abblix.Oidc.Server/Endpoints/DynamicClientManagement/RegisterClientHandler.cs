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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation of <see cref="IRegisterClientHandler"/> that runs validation
/// (RFC 7591 §2 metadata + OIDC DCR 1.0) followed by processing (credential issuance,
/// persistence, and registration access token generation per RFC 7591 §3.2.1 / RFC 7592 §3).
/// </summary>
/// <param name="validator">Validator for the raw registration metadata.</param>
/// <param name="processor">Processor that persists the client and constructs the response.</param>
public class RegisterClientHandler(
    IRegisterClientRequestValidator validator,
    IRegisterClientRequestProcessor processor) : IRegisterClientHandler
{
    /// <summary>
    /// Validates the registration metadata, then provisions the client and returns the
    /// RFC 7591 §3.2.1 success response or an error per §3.2.2.
    /// </summary>
    /// <param name="clientRegistrationRequest">The client metadata payload.</param>
    public async Task<Result<ClientRegistrationSuccessResponse, OidcError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRegistrationRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
