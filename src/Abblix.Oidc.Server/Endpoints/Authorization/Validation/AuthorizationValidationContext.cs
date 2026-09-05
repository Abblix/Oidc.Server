// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Encapsulates the context necessary for validating an authorization request, including client details,
/// response modes, and the OAuth 2.0 flow type.
/// </summary>
public record AuthorizationValidationContext(AuthorizationRequest Request)
{
	/// <summary>
	/// The authorization request to be validated. This includes all the details provided by the client
	/// for the authorization process.
	/// </summary>
	public AuthorizationRequest Request { get; set; } = Request;

	private ClientInfo? _clientInfo;

	/// <summary>
	/// Provides details about the client making the authorization request. This includes identifying information
	/// such as client ID and any other relevant data that has been registered with the authorization server.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when trying to access this property before it is set.
	/// </exception>
	public ClientInfo ClientInfo { get => _clientInfo.NotNull(nameof(ClientInfo)); set => _clientInfo = value; }

	/// <summary>
	/// Specifies how the authorization response should be delivered to the client, e.g., via a direct query or fragment.
	/// </summary>
	public string ResponseMode { get; set; } = ResponseModes.Query;

	private FlowTypes? _flowType;

	/// <summary>
	/// Identifies the OAuth 2.0 flow used in the authorization request, such as Authorization Code or Implicit.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when trying to access this property before it is set.
	/// </exception>
	public FlowTypes FlowType { get => _flowType.NotNull(nameof(FlowType)); set => _flowType = value; }

	/// <summary>
	/// The redirect URI where the response to the authorization request should be sent. This URI must be one of the
	/// registered URIs for the client to ensure security.
	/// </summary>
	public Uri? ValidRedirectUri { get; set; }

	/// <summary>
	/// A collection of scope definitions applicable to the authorization request, determining the permissions granted.
	/// </summary>
	public ScopeDefinition[] Scope { get; set; } = [];

	/// <summary>
	/// A collection of resource definitions that may be requested as part of the authorization process,
	/// providing additional control over the accessible resources.
	/// </summary>
	public ResourceDefinition[] Resources { get; set; } = [];

	/// <summary>
	/// The RFC 9396 Rich Authorization Requests array after per-type and per-client validation by
	/// <see cref="IAuthorizationDetailsPolicy"/>, stored as the
	/// raw <see cref="JsonArray"/> so byte-exact content survives forward to the grant.
	/// <c>null</c> when the request did not include <c>authorization_details</c>.
	/// </summary>
	public JsonArray? AuthorizationDetails { get; set; }

	/// <summary>
	/// The end user the request's <c>id_token_hint</c> names, as that ID token spells it, or <c>null</c>
	/// when the request carried no hint.
	/// </summary>
	/// <remarks>
	/// Spelled as the ID token has it, which for a pairwise client is the pseudonym sealed to that client's
	/// sector rather than the subject a session carries. Whoever compares the two converts the session
	/// forward; opening the pseudonym would fail whenever it could not be opened, and a comparison that
	/// could not be made must not read as a match.
	/// </remarks>
	public string? IdTokenHintSubject { get; set; }

	/// <summary>
	/// The end users the request's <c>claims</c> parameter will accept for <c>sub</c>, or <c>null</c> when it
	/// asked for none in particular. An empty array accepts nobody.
	/// </summary>
	/// <remarks>
	/// A second, independent constraint rather than an alternative spelling of
	/// <see cref="IdTokenHintSubject"/>: a request may carry both, and OpenID Connect Core 1.0 Section 3.1.2.2
	/// obliges the server to honour whichever are present. Spelled the way the client wrote them, so the same
	/// conversion applies - a pairwise client names the pseudonym sealed to its own sector.
	/// <para>
	/// Empty is a state a request can genuinely reach, by naming a <c>value</c> absent from its own
	/// <c>values</c>. That mismatch is what Section 5.5.1 says "MUST cause the authentication to fail", so it
	/// is carried through as a constraint nobody satisfies rather than discarded as nonsense.
	/// </para>
	/// </remarks>
	public string[]? RequestedSubjects { get; set; }
}
