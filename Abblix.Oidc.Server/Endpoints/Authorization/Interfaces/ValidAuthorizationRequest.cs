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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Represents an authorization request that has passed validation, encapsulating all necessary information
/// resolved during its validation.
/// </summary>
public record ValidAuthorizationRequest : AuthorizationRequestValidationResult
{
	public ValidAuthorizationRequest(AuthorizationValidationContext context)
		: base(context.ResponseMode)
	{
		Model = context.Request;
		ClientInfo = context.ClientInfo;
		Scope = context.Scope;
		Resources = context.Resources;
	}
	/// <summary>
	/// The original or recovered request model that was validated.
	/// </summary>
	public AuthorizationRequest Model { get; init; }

	/// <summary>
	/// Information about the client making the request, as determined during validation.
	/// </summary>
	public ClientInfo ClientInfo { get; init; }

	/// <summary>
	/// The scope associated with the authorization request, indicating the permissions requested by the client.
	/// </summary>
	public ScopeDefinition[] Scope { get; set; }

	/// <summary>
	/// The resources associated with the authorization request, detailing the specific resources the client
	/// is requesting access to.
	/// </summary>
	public ResourceDefinition[] Resources { get; set; }
}
