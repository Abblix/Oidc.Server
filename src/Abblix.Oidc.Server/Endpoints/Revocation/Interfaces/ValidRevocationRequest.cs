// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents a valid revocation request, including the request model and the associated token, if available.
/// </summary>
public record ValidRevocationRequest
{
	/// <summary>
	/// Initializes a valid revocation request with the provided model and token.
	/// </summary>
	public ValidRevocationRequest(RevocationRequest model, JsonWebToken token)
	{
		Model = model;
		Token = token;
	}

	/// <summary>
	/// Creates a valid revocation request for an invalid token without a token association.
	/// </summary>
	/// <remarks>
	/// Invalid tokens do not cause an error response since the client cannot handle such an error in a reasonable way.
	/// Moreover, the purpose of the revocation request, invalidating the particular token, is already achieved.
	/// See https://www.rfc-editor.org/rfc/rfc7009#section-2.2
	/// </remarks>
	public static ValidRevocationRequest InvalidToken(RevocationRequest model) => new(model);

	/// <inheritdoc />
	private ValidRevocationRequest(RevocationRequest model)
	{
		Model = model;
		Token = null;
	}

	/// <summary>
	/// The revocation request model.
	/// </summary>
	public RevocationRequest Model { get; }

	/// <summary>
	/// The associated token, if available.
	/// </summary>
	public JsonWebToken? Token { get; }
}
