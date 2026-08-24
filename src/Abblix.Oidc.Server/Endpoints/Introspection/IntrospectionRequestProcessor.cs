// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
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
/// <param name="clientInfoProvider">Resolves the client a token was issued to, so its subject can be opened
/// before being re-sealed for a different caller.</param>
/// <param name="subjectTypeConverter">Opens and re-seals the end-user identifier per client sector.</param>
public class IntrospectionRequestProcessor(
	IClientInfoProvider clientInfoProvider,
	ISubjectTypeConverter subjectTypeConverter) : IIntrospectionRequestProcessor
{
	/// <summary>
	/// Processes an introspection request and returns the corresponding introspection response.
	/// </summary>
	/// <param name="request">The valid introspection request to process. It contains the token to be introspected.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, with a result of <see cref="IntrospectionSuccess"/>
	/// or an <see cref="OidcError"/>. The response indicates the active status of the token and contains associated claims.
	/// </returns>
	public async Task<Result<IntrospectionSuccess, OidcError>> ProcessAsync(ValidIntrospectionRequest request)
		=> await ProcessInternalAsync(request);

	private async Task<IntrospectionSuccess> ProcessInternalAsync(ValidIntrospectionRequest request)
	{
		if (request.Token == null)
		{
			// https://www.rfc-editor.org/rfc/rfc7662#section-2.2: 

			// If the introspection call is properly authorized but the token is not active, does not exist on this server,
			// or the protected resource is not allowed to introspect this particular token, then the authorization server
			// MUST return an introspection response with the "active" field set to "false".

			// Note that to avoid disclosing too much of the authorization server's state to a third party, the authorization server
			// SHOULD NOT include any additional information about an inactive token, including why the token is inactive.
			return new IntrospectionSuccess(false, null, request.ClientInfo);
		}

		// The authorization server MAY respond differently to different protected resources making the same request.
		// For instance, an authorization server MAY limit which scopes from a given token are returned for each protected resource
		// to prevent a protected resource from learning more about the larger network than is necessary for its operation.

		// A pairwise client's 'sub' is its own opaque per-sector pseudonym - meaningful only to the issuing server
		// (which can reverse it) - so echoing the payload as-is leaks nothing extra to the client the token was
		// issued to. That reasoning does not carry to any other caller: the pseudonym belongs to somebody else's
		// sector, and handing it over gives the caller a stable handle on a user it was never told about.
		var payload = request.Token.Payload.Json;
		if (request.Token.Payload.ClientId != request.ClientInfo.ClientId)
		{
			payload = WithoutPrivateClaims(payload, request.ClientInfo);

			var pseudonym = await PseudonymForCallerAsync(request);
			if (pseudonym != null)
			{
				payload[IanaClaimTypes.Sub] = pseudonym;
			}
		}

		return new IntrospectionSuccess(true, payload, request.ClientInfo);
	}

	/// <summary>
	/// Produces the identifier by which the calling protected resource knows this end-user, or <c>null</c> when
	/// there is none to give and the subject stays withheld.
	/// </summary>
	/// <remarks>
	/// RFC 7662 Section 5 offers this as the alternative to withholding: "transmit user identifiers as opaque
	/// service-specific strings, potentially returning different identifiers to each protected resource". A
	/// pairwise caller already has such a namespace, so the subject is opened back to the real user and
	/// re-sealed to the caller's sector - it gets a stable handle that says nothing about the real subject and
	/// cannot be matched against what another resource sees.
	/// <para>
	/// A caller that is not pairwise gets nothing. Its own subject type says it sees users under their real
	/// identifiers, which is a statement about the tokens issued to it, not a licence to learn the identity of
	/// a user who authorized somebody else.
	/// </para>
	/// Anything uncertain also yields nothing: an owner that no longer resolves, or a subject that will not
	/// open, leaves the response as it would have been without this.
	/// </remarks>
	private async Task<string?> PseudonymForCallerAsync(ValidIntrospectionRequest request)
	{
		if (request.ClientInfo.SubjectType != SubjectTypes.Pairwise)
			return null;

		var token = request.Token.NotNull(nameof(request.Token));
		if (token.Payload.Subject is not { } subject || token.Payload.ClientId is not { } ownerId)
			return null;

		// The subject in the token is what its own client sees, so it has to be opened against that client
		// before it can be re-sealed for anybody else.
		var owner = await clientInfoProvider.TryFindClientAsync(ownerId).WithLicenseCheck();
		if (owner == null)
			return null;

		var realSubject = subjectTypeConverter.ConvertBack(subject, owner);
		return realSubject == null ? null : subjectTypeConverter.Convert(realSubject, request.ClientInfo);
	}

	/// <summary>
	/// The members RFC 7662 Section 2.2 defines that carry nothing about the end-user, which is what a caller
	/// other than the token's own client receives.
	/// </summary>
	/// <remarks>
	/// This is an allow list rather than a list of claims to strip, because the payload is open-ended: scopes,
	/// authorization details and host-defined claims all live there, and a deny list only withholds what
	/// whoever wrote it happened to think of. Section 2.2 names the members a protected resource can expect,
	/// so anything outside it is something the caller was never promised.
	/// </remarks>
	private static readonly string[] ClaimsSafeForAnyCaller =
	[
		IanaClaimTypes.Iss,
		IanaClaimTypes.Aud,
		IanaClaimTypes.Exp,
		IanaClaimTypes.Nbf,
		IanaClaimTypes.Iat,
		IanaClaimTypes.Jti,
		IanaClaimTypes.Scope,
		IanaClaimTypes.ClientId,
	];

	/// <summary>
	/// Keeps only the members safe for a caller the token was not issued to.
	/// </summary>
	/// <remarks>
	/// RFC 7662 Section 5: "measures MUST be taken to prevent disclosure of this information to unintended
	/// parties", naming user identifiers as the case in point, and "omitting privacy-sensitive information from
	/// an introspection response is the simplest way of minimizing privacy issues". Section 2.2 grants the
	/// latitude to answer such a caller differently.
	/// </remarks>
	private static JsonObject WithoutPrivateClaims(JsonObject payload, ClientInfo caller)
	{
		var narrowed = new JsonObject();
		foreach (var name in ClaimsSafeForAnyCaller)
		{
			if (payload.TryGetPropertyValue(name, out var value) && value is not null)
			{
				narrowed[name] = value.DeepClone();
			}
		}

		AddAuthorizationDetailsAddressedTo(caller, payload, narrowed);
		return narrowed;
	}

	/// <summary>
	/// Adds the RFC 9396 <c>authorization_details</c> entries this caller is the resource server for.
	/// </summary>
	/// <remarks>
	/// RFC 9396 §9: "In order to enable the RS to enforce the authorization details as approved in the
	/// authorization process, the AS MUST make this data available to the RS", by the access token or by
	/// introspection. §9.2 governs the shape when it comes this way: the member carries "the same
	/// structure defined in Section 2, potentially filtered and extended for the RS making the
	/// introspection request", which is the filter applied here.
	/// <para>
	/// An entry reaches a caller only by naming it in <c>locations</c>. An entry without them is
	/// addressed to nobody in particular and stays withheld: §2.2 makes <c>locations</c> optional, so
	/// its absence says the client did not name a resource server, not that every one may read it.
	/// </para>
	/// <para>
	/// Addresses are compared as TEXT, byte for byte. RFC 9396 §12: "All string comparisons in an
	/// authorization_details parameter are to be done as defined by [RFC8259]. No additional
	/// transformation or normalization is to be done in evaluating equivalence of string values."
	/// Parsing both sides into <see cref="Uri"/> and comparing those would be that transformation, and
	/// it decides in the disclosing direction: it folds case, elides a default port, collapses dot
	/// segments, decodes percent-escapes and ignores a fragment, so <c>https://api.example.com/accounts/../payments</c>
	/// written by the CLIENT would open the payments resource server's entry to the accounts one.
	/// The registered side stays <see cref="Uri"/> because a host writing a location that is not one
	/// should hear about it where it was written; only the comparison is textual.
	/// </para>
	/// <para>
	/// What is disclosed is filtered too. §9.2 allows the member to be "filtered and extended for the RS
	/// making the introspection request", and §13 asks that this data be shared "on a 'need to know'
	/// basis": the entry goes out with its <c>locations</c> reduced to the ones this caller matched, so
	/// one resource server does not learn the addresses of the others from an entry naming several.
	/// </para>
	/// </remarks>
	private static void AddAuthorizationDetailsAddressedTo(
		ClientInfo caller,
		JsonObject payload,
		JsonObject narrowed)
	{
		if (caller.ResourceLocations is not { Length: > 0 } callerLocations ||
		    payload[IanaClaimTypes.AuthorizationDetails] is not JsonArray details)
			return;

		var registered = callerLocations
			.Select(location => location.OriginalString)
			.ToHashSet(StringComparer.Ordinal);

		var addressed = new JsonArray();
		foreach (var detail in details.ToTypedArray() ?? [])
		{
			if (detail.Locations is not { } locations)
				continue;

			var matched = locations.Where(registered.Contains).ToArray();
			if (matched.Length == 0)
				continue;

			// Written as an array rather than through the typed setter, which collapses a single value
			// to a bare string: §9.2 has the member carry "the same structure defined in Section 2", and
			// §2.2 defines locations as an array of strings.
			var disclosed = (JsonObject)detail.Json.DeepClone();
			disclosed[AuthorizationDetail.Parameters.Locations] = new JsonArray(
				matched.Select(location => (JsonNode)JsonValue.Create(location)).ToArray());

			addressed.Add(disclosed);
		}

		if (addressed.Count > 0)
		{
			narrowed[IanaClaimTypes.AuthorizationDetails] = addressed;
		}
	}
}
