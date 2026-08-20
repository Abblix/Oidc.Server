// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// <para>
/// This is the response-stage error type, a variant of the <see cref="AuthorizationResponse"/> polymorphic
/// hierarchy alongside <see cref="LoginRequired"/>, <see cref="ConsentRequired"/>,
/// <see cref="SuccessfullyAuthenticated"/> etc. The validator pipeline produces the lighter
/// <see cref="AuthorizationRequestValidationError"/>; this type wraps it (via the secondary constructor)
/// with the originating <c>Model</c> needed for state propagation through the formatter, plus the optional
/// <c>error_uri</c>.
/// </para>
/// <para>
/// Two parallel error types exist because of the layered architecture: the validator pipeline operates on
/// the generic <see cref="Abblix.Utils.Result{TSuccess,TFailure}"/> envelope and stays free of response-level
/// concerns. The cost is field duplication (<c>Error</c>, <c>ErrorDescription</c>, <c>ResponseMode</c>,
/// <c>RedirectUri</c>) - accepted for the architectural seam.
/// </para>
/// </remarks>
public record AuthorizationError(
	AuthorizationRequest Model,
	string Error,
	string ErrorDescription,
	string ResponseMode,
	Uri? RedirectUri,
	Uri? ErrorUri = null)
	: ClientDeliveredResponse(Model, ResponseMode)
{
	/// <summary>
	/// Constructs an instance of <see cref="AuthorizationError"/> from an <see cref="AuthorizationRequest"/> and
	/// an <see cref="AuthorizationRequestValidationError"/>.
	/// </summary>
	/// <param name="request">The request that resulted in the error.</param>
	/// <param name="error">The validation error that provides details about what caused the request to fail.</param>
	public AuthorizationError(AuthorizationRequest request, AuthorizationRequestValidationError error)
		: this(
			request,
			error.Error,
			error.ErrorDescription,
			error.ResponseMode,
			error.RedirectUri)
	{
	}
}
