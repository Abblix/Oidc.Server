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
/// Provides a base for implementing synchronous authorization request validation steps.
/// This abstract class allows for creating validators that perform synchronous validation
/// of authorization requests, while adhering to the <see cref="IAuthorizationContextValidator"/>
/// interface for asynchronous operation.
/// </summary>
public abstract class SyncAuthorizationContextValidatorBase : IAuthorizationContextValidator
{
	/// <summary>
	/// Synchronously validates the authorization request and wraps the result in a task.
	/// This method implements the <see cref="IAuthorizationContextValidator.ValidateAsync"/> method
	/// to allow synchronous validation logic within an asynchronous method signature.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// A task representing the result of the synchronous validation. The task contains an
	/// <see cref="AuthorizationRequestValidationError"/> if the validation fails, or null if the request is valid.
	/// </returns>
	public Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
		=> Task.FromResult(Validate(context));

	/// <summary>
	/// Abstract method for validating the authorization request.
	/// Derived classes must implement this method to provide specific validation logic.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError"/> if the validation fails, or null if the request is valid.
	/// </returns>
	protected abstract AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context);
}
