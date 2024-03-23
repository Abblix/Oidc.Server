// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
	private static AuthorizationRequestValidationError ValidationError(string error, string description) => new(
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
}
