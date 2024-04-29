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
