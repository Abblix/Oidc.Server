// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
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
/// <param name="AuthorizationDetails">RFC 9396 §3 Rich Authorization Requests array
/// (already passed the per-client allowlist and per-type validator dispatch) which the
/// downstream processor threads onto the issued grant's AuthorizationContext byte-exact.</param>
public record ValidBackChannelAuthenticationRequest(
	BackChannelAuthenticationRequest Model,
	ClientInfo ClientInfo,
	TimeSpan ExpiresIn,
	JsonWebToken? LoginHintToken,
	JsonWebToken? IdToken,
	ScopeDefinition[] Scope,
	ResourceDefinition[] Resources,
	JsonArray? AuthorizationDetails)
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
			context.Resources,
			context.AuthorizationDetails)
	{
	}
}
