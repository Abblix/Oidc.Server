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

using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Implements the logic for processing introspection requests and generating introspection responses.
/// </summary>
/// <remarks>
/// This class handles the introspection of tokens to determine if they are active or inactive.
/// It follows the OAuth 2.0 Token Introspection specification (RFC 7662).
/// The processor examines the token's status and provides an appropriate response as per the specification.
/// </remarks>
public class IntrospectionRequestProcessor : IIntrospectionRequestProcessor
{
	/// <summary>
	/// Processes an introspection request and returns the corresponding introspection response.
	/// </summary>
	/// <param name="request">The valid introspection request to process. It contains the token to be introspected.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, with a result of <see cref="IntrospectionResponse"/>.
	/// The response indicates the active status of the token and contains associated claims.
	/// </returns>
	public Task<Result<IntrospectionSuccess, IntrospectionError>> ProcessAsync(ValidIntrospectionRequest request) => Task.FromResult<Result<IntrospectionSuccess, IntrospectionError>>(Process(request));

	private static IntrospectionSuccess Process(ValidIntrospectionRequest request)
	{
		if (request.Token == null)
		{
			// https://www.rfc-editor.org/rfc/rfc7662#section-2.2: 

			// If the introspection call is properly authorized but the token is not active, does not exist on this server,
			// or the protected resource is not allowed to introspect this particular token, then the authorization server
			// MUST return an introspection response with the "active" field set to "false".

			// Note that to avoid disclosing too much of the authorization server's state to a third party, the authorization server
			// SHOULD NOT include any additional information about an inactive token, including why the token is inactive.
			return new IntrospectionSuccess(false, null);
		}

		// The authorization server MAY respond differently to different protected resources making the same request.
		// For instance, an authorization server MAY limit which scopes from a given token are returned for each protected resource
		// to prevent a protected resource from learning more about the larger network than is necessary for its operation.

		return new IntrospectionSuccess(true, request.Token.Payload.Json);
	}
}
