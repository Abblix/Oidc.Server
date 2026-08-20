// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Defines the contract for a validator in an authorization context.
/// Implementations of this interface should provide logic for validating
/// authorization requests.
/// </summary>
public interface IAuthorizationContextValidator
{
	/// <summary>
	/// Asynchronously validates an authorization request within a given context.
	/// </summary>
	/// <param name="context">
	/// The <see cref="AuthorizationValidationContext"/> that contains the details
	/// of the authorization request to be validated.
	/// </param>
	/// <returns>
	/// A task that represents the asynchronous validation operation. The task result contains
	/// an <see cref="AuthorizationRequestValidationError"/> if a validation error is found,
	/// or null if validation is successful.
	/// </returns>
	Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context);
}
