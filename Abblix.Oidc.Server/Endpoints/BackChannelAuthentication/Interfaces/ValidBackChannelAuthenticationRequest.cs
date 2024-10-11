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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// Represents a validated backchannel authentication request, encapsulating the original request model
/// and the associated client information.
/// </summary>
/// <param name="Model">The original backchannel authentication request that passed validation.</param>
/// <param name="ClientInfo">The information about the client associated with the request,
/// including credentials and other metadata.</param>
/// <param name="ExpiresIn">The expiry duration for the backchannel authentication request,
/// defining how long the request remains valid.</param>
/// <param name="LoginHintToken">The login hint token, if provided,
/// which can be used to identify the user in the request.</param>
/// <param name="IdToken">The ID token, if provided, used to validate the user's identity in the request.</param>
/// <param name="Scope">The set of scope definitions applicable to the request,
/// indicating the permissions requested by the client.</param>
/// <param name="Resources">The set of resources requested as part of the authorization process,
/// specifying the accessible resources for the client.</param>
public record ValidBackChannelAuthenticationRequest(
	BackChannelAuthenticationRequest Model,
	ClientInfo ClientInfo,
	TimeSpan ExpiresIn,
	JsonWebToken? LoginHintToken,
	JsonWebToken? IdToken,
	ScopeDefinition[] Scope,
	ResourceDefinition[] Resources)
	: BackChannelAuthenticationValidationResult
{
	/// <summary>
	/// Initializes a new instance of the <see cref="ValidBackChannelAuthenticationRequest"/> class using
	/// the specified validation context.
	/// </summary>
	/// <param name="context">The validation context containing the original request and client information.</param>
	public ValidBackChannelAuthenticationRequest(BackChannelAuthenticationValidationContext context)
		:this(
			context.Request,
			context.ClientInfo,
			context.ExpiresIn,
			context.LoginHintToken,
			context.IdToken,
			context.Scope,
			context.Resources)
	{
	}
}
