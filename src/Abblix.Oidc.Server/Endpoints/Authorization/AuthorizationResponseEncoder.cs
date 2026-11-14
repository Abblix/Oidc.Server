// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResponseObject;
using P = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Default <see cref="IAuthorizationResponseEncoder"/>. Applies the <c>iss</c> (RFC 9207) and
/// implicit/hybrid <c>scope</c> gating, and - for a JARM (<c>*.jwt</c>) response mode - packs the
/// response parameters into a signed/encrypted <c>response</c> JWT and resolves the delivery mode.
/// Mutates the response, or replaces it with an error when its JWT cannot be produced, and returns the one to
/// deliver; the transport layer only maps the encoded response onto the wire.
/// </summary>
/// <param name="authorizationMetadata">Tells whether <c>iss</c> is advertised/emitted.</param>
/// <param name="responseJwtBuilder">Builds the JARM <c>response</c> JWT.</param>
public class AuthorizationResponseEncoder(
	IAuthorizationMetadataProvider authorizationMetadata,
	IResponseJwtBuilder responseJwtBuilder) : IAuthorizationResponseEncoder
{
	/// <inheritdoc />
	public async Task<AuthorizationResponse> EncodeAsync(TenantDefinition tenant, AuthorizationResponse response)
	{
		switch (response)
		{
			case SuccessfullyAuthenticated success:
			{
				// Scope rides the authorization response only for implicit/hybrid flows (OIDC Core
				// section 3.2.2.5 / section 3.3.2.5), where the response itself carries tokens. The code flow returns
				// only code + state (+ optional iss per RFC 9207); emitting scope there is flagged by
				// OIDF Conformance as "unexpected parameters" and disallowed by FAPI 2.0 section 5.3.1.
				// The value is the GRANTED scope (matching the issued token), not the requested set, so a
				// consent-narrowed grant is advertised truthfully per RFC 6749 section 3.3.
				var carriesTokens = success is { AccessToken: not null } or { IdToken: not null };
				success.Issuer = IssuerOf(tenant);
				success.Scope = carriesTokens ? string.Join(' ', success.GrantedScopes) : null;

				return await PackJwtAsync(tenant, success, carriesTokens, SuccessParameters(success));
			}

			// Errors are JARM-packed only when delivered to a redirect URI; non-redirectable errors
			// (e.g. an invalid redirect_uri) are surfaced directly by the transport, not redirected.
			case AuthorizationError { RedirectUri: not null } error:
			{
				var carriesTokens = error.Model.ResponseType is { } responseType && (
					responseType.Contains(ResponseTypes.Token) ||
					responseType.Contains(ResponseTypes.IdToken));

				error.Issuer = IssuerOf(tenant);

				return await PackJwtAsync(tenant, error, carriesTokens, ErrorParameters(error));
			}

			// Interaction responses (login/consent/account-selection) redirect to the AS's own UI,
			// not the client, so JARM does not apply - leave them untouched.
			default:
				return response;
		}
	}

	/// <summary>
	/// The <c>iss</c> value to place on the response, or null when the server does not advertise it.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	private string? IssuerOf(TenantDefinition tenant) => authorizationMetadata.AuthorizationResponseIssParameterSupported
		? tenant.Issuer.OriginalString
		: null;

	/// <summary>
	/// When the response mode is a JARM <c>*.jwt</c> mode, packs the supplied parameters into the
	/// <c>response</c> JWT and resolves the plaintext delivery mode; otherwise a no-op.
	/// </summary>
	/// <remarks>
	/// JARM says nothing of a response JWT the server cannot produce; when the client asked for its responses
	/// encrypted and publishes no key one can be encrypted to, the response goes to the redirect URI in the plain mode
	/// the JARM mode delivers through, as the error response of RFC 6749 section 4.1.2.1: an error stays the error it
	/// was, and a success becomes unauthorized_client, which is what the client cannot be issued to. This plain-mode
	/// error is outside JARM: section 2.1 wants an error response inside the JWT, and a strict JARM client, which
	/// processes nothing before the JWT checks of section 2.4 succeed, discards it; it only spares the request a server
	/// error.
	/// </remarks>
	private async Task<AuthorizationResponse> PackJwtAsync(
		TenantDefinition tenant,
		ClientDeliveredResponse response,
		bool carriesTokens,
		IReadOnlyList<(string name, string? value)> parameters)
	{
		if (!response.ResponseMode.IsJwtMode())
			return response;

		var deliveryMode = response.ResponseMode.ToDeliveryMode(carriesTokens);
		var built = await responseJwtBuilder.BuildAsync(tenant, response.Model.ClientId, parameters);
		if (built.TryGetFailure(out var refusal))
		{
			if (response is AuthorizationError error)
			{
				error.ResponseMode = deliveryMode;
				return error;
			}

			return new AuthorizationError(
				response.Model,
				ErrorCodes.UnauthorizedClient,
				refusal.ErrorDescription,
				deliveryMode,
				response.Model.RedirectUri) { Issuer = response.Issuer };
		}

		response.ResponseJwt = built.GetSuccess();
		response.ResponseMode = deliveryMode;
		return response;
	}

	private static IReadOnlyList<(string name, string? value)> SuccessParameters(SuccessfullyAuthenticated success) =>
	[
		(P.State, success.Model.State),
		(P.Issuer, success.Issuer),
		(P.Scope, success.Scope),
		(P.Code, success.Code),
		(P.TokenType, success.TokenType),
		(P.AccessToken, success.AccessToken?.EncodedJwt),
		(P.IdToken, success.IdToken?.EncodedJwt),
		(P.SessionState, success.SessionState),
	];

	private static IReadOnlyList<(string name, string? value)> ErrorParameters(AuthorizationError error) =>
	[
		(P.State, error.Model.State),
		(P.Issuer, error.Issuer),
		(P.Error, error.Error),
		(P.ErrorDescription, error.ErrorDescription),
		(P.ErrorUri, error.ErrorUri?.OriginalString),
	];
}
