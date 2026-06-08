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

using System;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Output of <see cref="IAuthorizationRequestValidator"/> handed to
/// <see cref="IAuthorizationRequestProcessor"/>. Snapshot of the data resolved during
/// validation: the wire-level request, the authenticated client, the negotiated response
/// mode (per OAuth 2.0 Multiple Response Types / Form Post), and the materialized scope and
/// resource definitions ready for consent and token issuance.
/// </summary>
public record ValidAuthorizationRequest
{
	/// <summary>
	/// Snapshots the validated state from the shared <see cref="AuthorizationValidationContext"/>
	/// once the validator pipeline has completed.
	/// </summary>
	public ValidAuthorizationRequest(AuthorizationValidationContext context)
	{
		ResponseMode = context.ResponseMode;
		Model = context.Request;
		RequestUri = context.Request.RequestUri;
		ClientInfo = context.ClientInfo;
		Scope = context.Scope;
		Resources = context.Resources;
		AuthorizationDetails = context.AuthorizationDetails;
	}

	/// <summary>
	/// The response mode to be used for delivering the authorization response.
	/// </summary>
	public string ResponseMode { get; init; }

	/// <summary>
	/// The original or recovered request model that was validated.
	/// </summary>
	public AuthorizationRequest Model { get; init; }

	/// <summary>
	/// The pushed authorization request URN (RFC 9126) this request was resolved from, or <c>null</c> when
	/// the request was not pushed. Surfaced here so the single-use decorator can consume it once a code or
	/// token has been issued, without reaching into <see cref="Model"/>.
	/// </summary>
	public Uri? RequestUri { get; init; }

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

	/// <summary>
	/// RFC 9396 Rich Authorization Requests array, snapshot from
	/// <see cref="AuthorizationValidationContext.AuthorizationDetails"/> at the end of the validator pipeline --
	/// i.e. post per-client allowlist filtering and post per-type validator narrow/extend mutations.
	/// <see cref="Features.Consents.IUserConsentsProvider"/> reads this slot to render the consent UI;
	/// downstream consent emits its (possibly further-narrowed) decision via
	/// <see cref="Features.Consents.ConsentDefinition.AuthorizationDetails"/>.
	/// <c>null</c> when the request did not include <c>authorization_details</c>.
	/// </summary>
	public JsonArray? AuthorizationDetails { get; init; }
}
