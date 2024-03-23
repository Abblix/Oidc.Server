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



namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Represents a valid introspection request result.
/// </summary>
public record ValidIntrospectionRequest : IntrospectionRequestValidationResult
{
	/// <summary>
	/// Initializes a new instance of the <see cref="ValidIntrospectionRequest"/> class.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	/// <param name="token">The JSON Web Token to introspect.</param>
	public ValidIntrospectionRequest(IntrospectionRequest model, JsonWebToken token)
	{
		Model = model;
		Token = token;
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="ValidIntrospectionRequest"/> class when the token is not provided.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	private ValidIntrospectionRequest(IntrospectionRequest model)
	{
		Model = model;
		Token = null;
	}

	/// <summary>
	/// Creates a valid introspection request for an invalid token.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	/// <returns>A valid introspection request with the "active" field set to "false."</returns>
	/// <remarks>
	/// See https://www.rfc-editor.org/rfc/rfc7662#section-5.2
	/// </remarks>
	public static ValidIntrospectionRequest InvalidToken(IntrospectionRequest model)
	{
		// Note that to avoid disclosing too much of the authorization server's state to a third party, the authorization server
		// SHOULD NOT include any additional information about an inactive token, including why the token is inactive.

		// That is why we do not return the token here even if it is valid, but for example it was issued for another client.
		return new(model);
	}

	/// <summary>
	/// The introspection request model.
	/// </summary>
	public IntrospectionRequest Model { get; }

	/// <summary>
	/// The JSON Web Token to introspect.
	/// </summary>
	public JsonWebToken? Token { get; }
}
