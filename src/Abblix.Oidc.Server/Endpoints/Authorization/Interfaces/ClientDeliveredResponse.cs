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
/// Base for the authorization responses that are delivered to the client's <c>redirect_uri</c>
/// (<see cref="SuccessfullyAuthenticated"/> and <see cref="AuthorizationError"/>), as opposed to the
/// interaction responses (<see cref="LoginRequired"/>, <see cref="ConsentRequired"/>, ...) that redirect
/// to the authorization server's own UI. These are the responses the
/// <see cref="IAuthorizationResponseEncoder"/> encodes: it sets the <c>iss</c> (RFC 9207) value, and for
/// a JARM (<c>*.jwt</c>) request packs the parameters into <see cref="ResponseJwt"/> and resolves
/// <see cref="ResponseMode"/> to its plaintext delivery counterpart.
/// </summary>
/// <param name="Model">The original or recovered request model that was processed.</param>
/// <param name="ResponseMode">The requested response mode (initial value of <see cref="ResponseMode"/>).</param>
public abstract record ClientDeliveredResponse(AuthorizationRequest Model, string ResponseMode)
	: AuthorizationResponse(Model)
{
	/// <summary>
	/// Specifies how the result is returned to the client. Carries the requested mode (including a
	/// JARM <c>*.jwt</c> mode) until the response encoder resolves it to the plaintext delivery mode.
	/// Settable so the encoder can update it in place after packing the JWT.
	/// </summary>
	public string ResponseMode { get; set; } = ResponseMode;

	/// <summary>
	/// The <c>iss</c> (RFC 9207) value to return on the response, populated by the response encoder when
	/// the server advertises it. <c>null</c> when issuer identification is not emitted.
	/// </summary>
	public string? Issuer { get; set; }

	/// <summary>
	/// The JARM (JWT Secured Authorization Response Mode) response JWT, populated by the response encoder
	/// when the client requested a <c>*.jwt</c> response mode. When set, it is the sole wire parameter and
	/// all other response parameters are carried as its claims. <c>null</c> for plaintext response modes.
	/// </summary>
	public string? ResponseJwt { get; set; }
}
