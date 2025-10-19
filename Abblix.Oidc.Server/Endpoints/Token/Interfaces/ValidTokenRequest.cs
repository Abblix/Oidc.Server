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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Represents a valid token request along with related authentication and authorization information.
/// </summary>
/// <param name="Model">The token request model containing the information required to process the token request.
/// </param>
/// <param name="AuthorizedGrant">The authorized grant result which encapsulates the result of the authorization
/// process.</param>
/// <param name="ClientInfo">Information about the client making the token request, including client credentials and
/// metadata.</param>
/// /// <param name="Scope">The scopes associated with the token request, indicating the permissions
/// requested by the client. </param>
/// <param name="Resources">The resources associated with the token request,
/// detailing the specific resources the client is requesting access to.</param>
public record ValidTokenRequest(
	TokenRequest Model,
	AuthorizedGrant AuthorizedGrant,
	ClientInfo ClientInfo,
	ScopeDefinition[] Scope,
	ResourceDefinition[] Resources)
{
	public ValidTokenRequest(TokenValidationContext context)
		: this(
			context.Request,
			context.AuthorizedGrant,
			context.ClientInfo,
			context.Scope,
			context.Resources)
	{
	}
}
