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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Represents an error response for an authorization request, detailing the nature of the error.
/// </summary>
/// <param name="Model">The original authorization request model that led to this error.</param>
/// <param name="Error">A single error code from the OAuth 2.0 specification that describes the error.</param>
/// <param name="ErrorDescription">A more detailed description of the error for debugging purposes.</param>
/// <param name="ResponseMode">The response mode to be used for returning parameters to the client.
/// This can influence how the error information is transmitted back to the client.</param>
/// <param name="RedirectUri">The URI to which the response should be sent. This is where the error information
/// will be transmitted if applicable.</param>
/// <param name="ErrorUri">A URI identifying a human-readable web page with information about the error.</param>
/// <remarks>
/// This record encapsulates information about errors encountered during the processing of an authorization request.
/// It includes details that can be returned to the client to indicate what went wrong. This structure facilitates
/// compliance with OAuth 2.0 and OpenID Connect specifications by providing a standardized format for error reporting.
/// </remarks>
public record AuthorizationError(
	AuthorizationRequest Model,
	string Error,
	string ErrorDescription,
	string ResponseMode,
	Uri? RedirectUri,
	Uri? ErrorUri = null)
	: AuthorizationResponse(Model)
{
	/// <summary>
	/// Constructs an instance of <see cref="AuthorizationError"/> from an <see cref="AuthorizationRequest"/> and
	/// an <see cref="AuthorizationRequestValidationError"/>.
	/// </summary>
	/// <param name="request">The request that resulted in the error.</param>
	/// <param name="error">The validation error that provides details about what caused the request to fail.</param>
	public AuthorizationError(AuthorizationRequest request, AuthorizationRequestValidationError error)
		: this(request,
			error.Error,
			error.ErrorDescription,
			error.ResponseMode,
			error.RedirectUri)
	{
	}
}
