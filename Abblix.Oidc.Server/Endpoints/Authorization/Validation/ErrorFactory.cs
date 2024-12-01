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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;

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
	/// Creates an <see cref="AuthorizationRequestValidationError"/> for a general invalid request error,
	/// without an associated validation context.
	/// </summary>
	/// <param name="description">A description of what was invalid about the request.</param>
	/// <returns>An <see cref="AuthorizationRequestValidationError"/> with the specified error details.</returns>
	public static AuthorizationRequestValidationError InvalidRequest(string description)
		=> ValidationError(ErrorCodes.InvalidRequest, description);

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
}
