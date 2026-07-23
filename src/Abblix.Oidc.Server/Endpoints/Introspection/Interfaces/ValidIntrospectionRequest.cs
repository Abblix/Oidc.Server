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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;

/// <summary>
/// Output of <see cref="IIntrospectionRequestValidator"/> handed to the processor: pairs the
/// original request with either the parsed token (active branch) or a <c>null</c> token
/// (inactive branch produced via <see cref="InvalidToken"/>, used so token-level failures
/// flow through the same processing path without disclosing why per RFC 7662 §2.2).
/// </summary>
public record ValidIntrospectionRequest
{
	/// <summary>
	/// Active-branch constructor: the token authenticated, was issued to this client and
	/// passed validation.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	/// <param name="clientInfo">The authenticated client making the introspection request; it determines the
	/// response format (plain JSON vs. a signed/encrypted JWT per RFC 9701).</param>
	/// <param name="token">The parsed JWT to be reported as <c>active=true</c>.</param>
	public ValidIntrospectionRequest(IntrospectionRequest model, ClientInfo clientInfo, JsonWebToken token)
	{
		Model = model;
		ClientInfo = clientInfo;
		Token = token;
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="ValidIntrospectionRequest"/> class when the token is not provided.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	/// <param name="clientInfo">The authenticated client making the introspection request.</param>
	private ValidIntrospectionRequest(IntrospectionRequest model, ClientInfo clientInfo)
	{
		Model = model;
		ClientInfo = clientInfo;
		Token = null;
	}

	/// <summary>
	/// Creates a valid introspection request for an invalid token.
	/// </summary>
	/// <param name="model">The introspection request model.</param>
	/// <param name="clientInfo">The authenticated client making the introspection request.</param>
	/// <returns>A valid introspection request with the "active" field set to "false."</returns>
	/// <remarks>
	/// See https://www.rfc-editor.org/rfc/rfc7662#section-5.2
	/// </remarks>
	public static ValidIntrospectionRequest InvalidToken(IntrospectionRequest model, ClientInfo clientInfo)
	{
		// Note that to avoid disclosing too much of the authorization server's state to a third party,
		// the authorization server SHOULD NOT include any additional information about an inactive token,
		// including why the token is inactive.

		// That is why we do not return the token here even if it is valid, but for example,
		// it was issued for another client.
		return new(model, clientInfo);
	}

	/// <summary>
	/// The introspection request model.
	/// </summary>
	public IntrospectionRequest Model { get; }

	/// <summary>
	/// The authenticated client making the introspection request, used to select the response format (RFC 9701).
	/// </summary>
	public ClientInfo ClientInfo { get; }

	/// <summary>
	/// The JSON Web Token to introspect.
	/// </summary>
	public JsonWebToken? Token { get; }
}
