// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines the interface for validating authorization requests in accordance with OpenID Connect Core 1.0
/// specifications. It assesses if a request complies with the required parameters and constraints for
/// authentication and authorization processes.
/// </summary>
/// <remarks>
/// For more details on authorization request validation, refer to the OpenID Connect Core 1.0 specification.
/// </remarks>
public interface IAuthorizationRequestValidator
{
	/// <summary>
	/// Asynchronously validates an authorization request against the OpenID Connect Core 1.0 specifications,
	/// ensuring it meets the required criteria for processing.
	/// </summary>
	/// <param name="request">The authorization request to validate.</param>
	/// <returns>A task that resolves to a validation result indicating the request's compliance with
	/// the specifications.</returns>
	Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(AuthorizationRequest request);
}
