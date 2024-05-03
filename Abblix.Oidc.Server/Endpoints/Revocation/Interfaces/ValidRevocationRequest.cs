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

using Abblix.Jwt;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents a valid revocation request, including the request model and the associated token, if available.
/// </summary>
public record ValidRevocationRequest : RevocationRequestValidationResult
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
