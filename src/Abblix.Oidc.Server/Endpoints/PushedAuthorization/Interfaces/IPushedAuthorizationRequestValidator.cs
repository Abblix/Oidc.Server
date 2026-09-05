// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

/// <summary>
/// Provides validation for pushed authorization requests in an OAuth 2.0 context, ensuring they adhere
/// to protocol specifications.
/// This interface evaluates the conformity of authorization requests with expected parameters and
/// limitations before their acceptance for processing.
/// </summary>
public interface IPushedAuthorizationRequestValidator
{
    /// <summary>
    /// Asynchronously validates a pushed authorization request against OAuth 2.0 specifications.
    /// This method ensures the request meets all necessary criteria and constraints defined for secure processing.
    /// </summary>
    /// <param name="authorizationRequest">The authorization request to be validated.</param>
    /// <param name="clientRequest">Additional client request information for contextual validation.</param>
    /// <returns>A task that upon completion provides a validation result, indicating either success and validity
    /// of the request or the presence of errors.</returns>
    Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest);
}
