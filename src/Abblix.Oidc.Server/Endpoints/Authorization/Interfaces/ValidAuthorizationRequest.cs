// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		RequestUri = context.Request.PushedRequestUri;
		ClientInfo = context.ClientInfo;
		Scope = context.Scope;
		Resources = context.Resources;
		AuthorizationDetails = context.AuthorizationDetails;
		IdTokenHintSubject = context.IdTokenHintSubject;
		RequestedSubjects = context.RequestedSubjects;
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
	/// The end user the request's <c>id_token_hint</c> names, as that ID token spells it, or <c>null</c>
	/// when the request carried no hint.
	/// </summary>
	/// <remarks>
	/// For a pairwise client this is the pseudonym sealed to that client's sector rather than the subject a
	/// session carries, so a comparison converts the session forward rather than opening this.
	/// </remarks>
	public string? IdTokenHintSubject { get; init; }

	/// <summary>
	/// The end users the request's <c>claims</c> parameter will accept for <c>sub</c>, or <c>null</c> when it
	/// asked for none in particular. An empty array accepts nobody.
	/// </summary>
	/// <remarks>
	/// Independent of <see cref="IdTokenHintSubject"/> - a request may state both, and both bind. Spelled the
	/// way the client wrote them, so a comparison converts the session forward rather than opening these.
	/// </remarks>
	public string[]? RequestedSubjects { get; init; }

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
