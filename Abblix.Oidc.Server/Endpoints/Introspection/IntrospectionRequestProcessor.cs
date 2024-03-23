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

using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;



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
	public Task<IntrospectionResponse> ProcessAsync(ValidIntrospectionRequest request) => Task.FromResult(Process(request));

	private static IntrospectionResponse Process(ValidIntrospectionRequest request)
	{
		if (request.Token == null)
		{
			// https://www.rfc-editor.org/rfc/rfc7662#section-2.2: 

			// If the introspection call is properly authorized but the token is not active, does not exist on this server,
			// or the protected resource is not allowed to introspect this particular token, then the authorization server
			// MUST return an introspection response with the "active" field set to "false".

			// Note that to avoid disclosing too much of the authorization server's state to a third party, the authorization server
			// SHOULD NOT include any additional information about an inactive token, including why the token is inactive.
			return new IntrospectionSuccessResponse(false, null);
		}

		// The authorization server MAY respond differently to different protected resources making the same request.
		// For instance, an authorization server MAY limit which scopes from a given token are returned for each protected resource
		// to prevent a protected resource from learning more about the larger network than is necessary for its operation.

		return new IntrospectionSuccessResponse(true, request.Token.Payload.Json);
	}
}
