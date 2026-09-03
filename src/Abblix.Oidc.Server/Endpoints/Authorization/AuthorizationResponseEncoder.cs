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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResponseObject;
using P = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Default <see cref="IAuthorizationResponseEncoder"/>. Applies the <c>iss</c> (RFC 9207) and
/// implicit/hybrid <c>scope</c> gating, and - for a JARM (<c>*.jwt</c>) response mode - packs the
/// response parameters into a signed/encrypted <c>response</c> JWT and resolves the delivery mode.
/// Mutates the response in place; the transport layer only maps the encoded response onto the wire.
/// </summary>
/// <param name="issuerProvider">Supplies the <c>iss</c> value (RFC 9207).</param>
/// <param name="authorizationMetadata">Tells whether <c>iss</c> is advertised/emitted.</param>
/// <param name="responseJwtBuilder">Builds the JARM <c>response</c> JWT.</param>
public class AuthorizationResponseEncoder(
	IIssuerProvider issuerProvider,
	IAuthorizationMetadataProvider authorizationMetadata,
	IResponseJwtBuilder responseJwtBuilder) : IAuthorizationResponseEncoder
{
	/// <inheritdoc />
	public async Task EncodeAsync(AuthorizationResponse response)
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
				success.Issuer = Issuer;
				success.Scope = carriesTokens ? string.Join(' ', success.GrantedScopes) : null;

				await PackJwtAsync(success, carriesTokens, SuccessParameters(success));
				break;
			}

			// Errors are JARM-packed only when delivered to a redirect URI; non-redirectable errors
			// (e.g. an invalid redirect_uri) are surfaced directly by the transport, not redirected.
			case AuthorizationError { RedirectUri: not null } error:
			{
				var carriesTokens = error.Model.ResponseType is { } responseType && (
					responseType.Contains(ResponseTypes.Token) ||
					responseType.Contains(ResponseTypes.IdToken));

				error.Issuer = Issuer;

				await PackJwtAsync(error, carriesTokens, ErrorParameters(error));
				break;
			}

			// Interaction responses (login/consent/account-selection) redirect to the AS's own UI,
			// not the client, so JARM does not apply - leave them untouched.
		}
	}

	/// <summary>
	/// The <c>iss</c> value to place on the response, or null when the server does not advertise it.
	/// </summary>
	private string? Issuer => authorizationMetadata.AuthorizationResponseIssParameterSupported
		? issuerProvider.GetIssuer()
		: null;

	/// <summary>
	/// When the response mode is a JARM <c>*.jwt</c> mode, packs the supplied parameters into the
	/// <c>response</c> JWT and resolves the plaintext delivery mode; otherwise a no-op.
	/// </summary>
	private async Task PackJwtAsync(
		ClientDeliveredResponse response,
		bool carriesTokens,
		IReadOnlyList<(string name, string? value)> parameters)
	{
		if (!response.ResponseMode.IsJwtMode())
			return;

		response.ResponseJwt = await responseJwtBuilder.BuildAsync(response.Model.ClientId, parameters);
		response.ResponseMode = response.ResponseMode.ToDeliveryMode(carriesTokens);
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
