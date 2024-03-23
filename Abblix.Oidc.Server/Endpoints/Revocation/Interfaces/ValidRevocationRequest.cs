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
