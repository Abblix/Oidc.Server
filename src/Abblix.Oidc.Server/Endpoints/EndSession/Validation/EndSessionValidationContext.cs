// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents the context for validating an end-session request.
/// </summary>
public record EndSessionValidationContext(EndSessionRequest Request)
{
	/// <summary>
	/// The request object to validate.
	/// </summary>
	public EndSessionRequest Request { get; set; } = Request;

	/// <summary>
	/// The ClientId associated with the request.
	/// </summary>
	public string? ClientId { get; set; } = Request.ClientId;

	/// <summary>
	/// The ClientInfo object containing information about the client.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when attempting to get a null value.</exception>
	public ClientInfo? ClientInfo { get; set; }

	/// <summary>
	/// The ID token associated with the end-session request.
	/// This token is typically used to validate the identity of the user who initiated the end-session process.
	/// </summary>
	public JsonWebToken? IdToken { get; set; }
}
