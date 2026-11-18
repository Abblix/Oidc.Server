// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Provides a factory for creating standardized authorization request error responses.
/// This factory simplifies the creation of error responses for various types of validation failures
/// during authorization request processing.
/// </summary>
public static class ErrorFactory
{
	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid request.
	/// This error type is commonly used when an authorization request fails due to missing or invalid parameters.
	/// </summary>
	/// <param name="context">The validation context associated with the request, providing additional context for
	/// the error response.</param>
	/// <param name="description">A human-readable explanation detailing what was invalid about the request.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError"/> instance encapsulating the error details.</returns>
	public static AuthorizationRequestValidationError InvalidRequest(
		this AuthorizationValidationContext context,
		string description)
	{
		return context.Error(ErrorCodes.InvalidRequest, description);
	}

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> for a general invalid request error,
	/// without an associated validation context.
	/// </summary>
	/// <param name="description">A description of what was invalid about the request.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> with the specified error details.</returns>
	public static AuthorizationRequestValidationError InvalidRequest(string description)
		=> ValidationError(ErrorCodes.InvalidRequest, description);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid client error.
	/// This error type is used when the client authentication fails or when the client is not authorized to perform
	/// the requested operation. It may occur due to issues like incorrect client credentials, unauthorized grant types
	/// for the client, or the client being unknown to the authorization server.
	/// </summary>
	/// <param name="description">A human-readable description specifying why the client is considered invalid.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> with the specified error details, indicating that
	/// the error relates to an invalid client.</returns>
	public static AuthorizationRequestValidationError InvalidClient(string description)
		=> ValidationError(ErrorCodes.InvalidClient, description);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid request URI.
	/// This error is used when the request_uri parameter of an authorization request is invalid or malformed.
	/// </summary>
	/// <param name="description">A description of the issue with the request URI.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> for the invalid request URI.</returns>
	public static AuthorizationRequestValidationError InvalidRequestUri(string description)
		=> ValidationError(ErrorCodes.InvalidRequestUri, description);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid request object.
	/// This error is used when the request object (JWT) in an authorization request is invalid, such as when
	/// signature validation fails or required claims are missing.
	/// </summary>
	/// <param name="description">A description of the issue with the request object.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> for the invalid request object.</returns>
	public static AuthorizationRequestValidationError InvalidRequestObject(string description)
		=> ValidationError(ErrorCodes.InvalidRequestObject, description);

	/// <summary>
	/// A private helper method to create an <see cref="AuthorizationRequestValidationError"/> with
	/// a specified error code and description.
	/// </summary>
	/// <param name="error">The error code as defined by the OpenID Connect and OAuth 2.0 specifications.</param>
	/// <param name="description">A human-readable description of the error.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError"/> instance with the specified error details.</returns>
	public static AuthorizationRequestValidationError ValidationError(string error, string description) => new(
		error,
		description,
		null,
		string.Empty);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> with a specified error code and description,
	/// using the context from an <see cref="AuthorizationValidationContext"/>.
	/// </summary>
	/// <param name="context">The validation context associated with the authorization request.</param>
	/// <param name="error">The error code as defined by the OpenID Connect and OAuth 2.0 specifications.</param>
	/// <param name="description">A human-readable description of the error.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError"/> instance encapsulating the error details.</returns>
	public static AuthorizationRequestValidationError Error(
		this AuthorizationValidationContext context,
		string error,
		string description) => new(
			error,
			description,
			context.ValidRedirectUri,
			context.ResponseMode);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid scope error.
	/// This error type is used when the scopes requested by the client are not supported or are inappropriate
	/// for the requested operation.
	/// </summary>
	/// <param name="context">The validation context associated with the request, providing additional context for
	/// the error response.</param>
	/// <param name="description">A human-readable description of why the requested scopes are invalid.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> with details about the scope-related issue.</returns>
	public static AuthorizationRequestValidationError InvalidScope(
		this AuthorizationValidationContext context,
		string description)
		=> context.Error(ErrorCodes.InvalidScope, description);

	/// <summary>
	/// Creates an <see cref="AuthorizationRequestValidationError"/> indicating an invalid
	/// <c>authorization_details</c> array per RFC 9396 section 5. Used when an entry references an
	/// unknown <c>type</c>, fails per-type schema validation, or is not in the per-client allowlist.
	/// </summary>
	/// <param name="context">The validation context associated with the request.</param>
	/// <param name="description">A human-readable description of the rejection cause.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> with the RAR-specific error code.</returns>
	public static AuthorizationRequestValidationError InvalidAuthorizationDetails(
		this AuthorizationValidationContext context,
		string description)
		=> context.Error(ErrorCodes.InvalidAuthorizationDetails, description);
}
