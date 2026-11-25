// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public class AuthorizationCodeGrantHandlerTests
{
	private readonly Mock<IAuthorizationCodeService> _authCodeService;
	private readonly AuthorizationCodeGrantHandler _handler;

	public AuthorizationCodeGrantHandlerTests()
	{
		_authCodeService = new Mock<IAuthorizationCodeService>(MockBehavior.Strict);

		_handler = new AuthorizationCodeGrantHandler(
			_authCodeService.Object);
	}

	/// <summary>
	/// RFC 6749 section 5.2: a token request without the required code parameter is the caller's protocol
	/// error and yields invalid_request - previously it threw and surfaced as HTTP 500.
	/// </summary>
	[Fact]
	public async Task AuthorizeAsync_MissingCode_ReturnsInvalidRequest()
	{
		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, new TokenRequest(), new ClientInfo("client1"), Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
	}

	/// <summary>
	/// RFC 6749 section 5.2 lists a code issued to another client explicitly under invalid_grant -
	/// previously this case was reported as unauthorized_client, which describes a client barred
	/// from the grant type itself.
	/// </summary>
	[Fact]
	public async Task AuthorizeAsync_CodeIssuedToAnotherClient_ReturnsInvalidGrant()
	{
		var authenticationTime = DateTimeOffset.Parse(
			"2026-06-11T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
		var tokenRequest = new TokenRequest { Code = "abc" };
		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", authenticationTime, "ip"),
					Context: new AuthorizationContext("original-client", [Scopes.OpenId], null)));

		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, new ClientInfo("another-client"), Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// Verifies that PKCE (Proof Key for Code Exchange) validation succeeds
	/// when the code verifier correctly matches the code challenge using both S256 and Plain methods.
	/// Tests RFC 7636 PKCE flow for OAuth 2.0 public clients.
	/// </summary>
	[Theory]
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
	[InlineData(CodeChallengeMethods.Plain, PlainVerifier, PlainVerifier)]
	public async Task PkceSuccessfulChallengeTest(string codeChallengeMethod, string codeChallenge, string codeVerifier)
	{
		var result = await PkceTest(codeChallengeMethod, codeChallenge, codeVerifier);

		// assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.NotNull(grant);
	}

	/// <summary>
	/// Verifies that PKCE validation fails and returns InvalidGrant error
	/// when the code verifier doesn't match the code challenge or is missing.
	/// This prevents authorization code interception attacks per RFC 7636.
	/// </summary>
	[Theory]
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", PlainVerifier)]
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", null)]
	[InlineData(CodeChallengeMethods.Plain, PlainVerifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
	[InlineData(CodeChallengeMethods.Plain, PlainVerifier, null)]
	// RFC 7636 section 4.6: the plain verifier is compared byte-for-byte, so a case flip must fail. This case
	// would have passed under the previous case-insensitive comparison - it locks the ordinal comparison in.
	[InlineData(CodeChallengeMethods.Plain, PlainVerifier, "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghj")]
	public async Task PkceFailureChallengeTest(string codeChallengeMethod, string codeChallenge, string? codeVerifier)
	{
		var result = await PkceTest(codeChallengeMethod, codeChallenge, codeVerifier);

		// assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 4.1.3: the code_verifier "MUST NOT be used" where no
	/// code_challenge was sent, and section 3.2.4 names a request that "contains a code_verifier although no
	/// code_challenge was sent in the authorization request" invalid_request. RFC 9700 section 2.1.1 reads it as a PKCE
	/// downgrade, so it is refused rather than ignored while tokens are issued.
	/// </summary>
	[Fact]
	public async Task AuthorizeAsync_CodeVerifierWithoutCodeChallenge_ReturnsInvalidRequest()
	{
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest { Code = "abc", CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" };

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)));

		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
	}

	/// <summary>
	/// OAuth 2.1 section 4.1.1: "code-verifier = 43*128unreserved". A verifier outside that syntax is a malformed
	/// request, invalid_request under section 3.2.4, rather than a grant the verifier fails to match; RFC 7636 section
	/// 4.6 keeps invalid_grant for a well-formed verifier that does not match, and for a missing one.
	/// </summary>
	[Theory]
	[InlineData("abc")]
	[InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX")]
	[InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk=")]
	[InlineData("dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk")]
	public async Task AMalformedCodeVerifier_ReturnsInvalidRequest(string codeVerifier)
	{
		var result = await PkceTest(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeVerifier);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
	}

	/// <summary>
	/// A code issued without a code_challenge and redeemed without a code_verifier is the ordinary
	/// non-PKCE flow and must still succeed - the downgrade guard only fires when a verifier is present.
	/// </summary>
	[Fact]
	public async Task AuthorizeAsync_NoCodeChallengeAndNoVerifier_Succeeds()
	{
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest { Code = "abc" };

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)));

		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

		Assert.True(result.TryGetSuccess(out var grant));
		Assert.NotNull(grant);
	}

	/// <summary>
	/// RFC 6749 section 4.1.3: the server must "ensure that the "redirect_uri" parameter is present if the
	/// "redirect_uri" parameter was included in the initial authorization request ... and if included ensure
	/// that their values are identical". Identical means the very string: a loopback redirect on another port
	/// (accepted at the authorization endpoint by RFC 8252 section 7.3), a path differing in case, and a spelling RFC
	/// 3986 normalizes to the same URI (host case, a default port, an encoded unreserved character) all fail.
	/// </summary>
	[Theory]
	[InlineData("https://client.example.com/callback2", "https://client.example.com/callback1")]
	[InlineData("http://127.0.0.1:51004/oauth2redirect", "http://127.0.0.1:51005/oauth2redirect")]
	[InlineData("https://client.example.com/callback", "https://client.example.com/Callback")]
	[InlineData("https://client.example.com/callback", "https://CLIENT.example.com/callback")]
	[InlineData("https://client.example.com/callback", "https://client.example.com:443/callback")]
	[InlineData("https://client.example.com/~user", "https://client.example.com/%7Euser")]
	[InlineData(null, "https://client.example.com/callback")]
	public async Task ARedirectUriOtherThanTheAuthorizationRequests_ReturnsInvalidGrant(
		string? authorizedRedirectUri,
		string? requestedRedirectUri)
	{
		foreach (var (pkce, namedNone) in new[] { (false, false), (true, false), (false, true), (true, true) })
		{
			var result = await RedeemWithRedirectUri(authorizedRedirectUri, requestedRedirectUri, pkce, namedNone);

			Assert.True(result.TryGetFailure(out var error));
			Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		}
	}

	/// <summary>
	/// RFC 6749 section 4.1.3, which OAuth 2.1 section 10.2 keeps for a code issued without PKCE: the redirect URI is
	/// "REQUIRED, if the "redirect_uri" parameter was included in the authorization request". A missing required
	/// parameter is invalid_request (OAuth 2.1 section 3.2.4).
	/// </summary>
	[Fact]
	public async Task ACodeWithoutPkce_ItsAuthorizationRequestNamingTheRedirectUri_RequiresIt()
	{
		var result = await RedeemWithRedirectUri("https://client.example.com/callback", null);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
	}

	/// <summary>
	/// OAuth 2.1 section 4.1.3 has the token request carry no redirect_uri, section 10.2 explaining that "authorization
	/// code injection is prevented by the code_challenge and code_verifier parameters, so including the redirect_uri
	/// parameter in the token request serves no purpose", so a code issued with PKCE is redeemed without it, whether or
	/// not its authorization request named one. RFC 6749 section 4.1.3 asks for none where the authorization request
	/// named none either.
	/// </summary>
	[Theory]
	[InlineData(true, false)]
	[InlineData(true, true)]
	[InlineData(false, true)]
	public async Task ACodeWithPkceOrIssuedToARequestNamingNoRedirectUri_IsRedeemedWithoutIt(bool pkce, bool namedNone)
	{
		var result = await RedeemWithRedirectUri("https://client.example.com/callback", null, pkce, namedNone);

		Assert.True(result.TryGetSuccess(out _));
	}

	/// <summary>
	/// OAuth 2.1 section 10.2: a server serving OAuth 2.0 clients too "MUST allow clients to send the redirect_uri
	/// parameter in the token request", so one sent for a code of any kind is accepted when it is the URI the code was
	/// issued at, the single registered one where the authorization request named none.
	/// </summary>
	[Theory]
	[InlineData(false, false)]
	[InlineData(true, false)]
	[InlineData(false, true)]
	[InlineData(true, true)]
	public async Task TheRedirectUriTheCodeWasIssuedAt_RedeemsAnyCode(bool pkce, bool namedNone)
	{
		const string uri = "https://client.example.com/callback";

		var result = await RedeemWithRedirectUri(uri, uri, pkce, namedNone);

		Assert.True(result.TryGetSuccess(out _));
	}

	/// <summary>
	/// A code stored without a redirect URI, as none of the authorization requests this server serves leaves, is
	/// redeemed without one.
	/// </summary>
	[Fact]
	public async Task ACodeWithoutARedirectUri_IsRedeemedWithoutOne()
	{
		var result = await RedeemWithRedirectUri(null, null);

		Assert.True(result.TryGetSuccess(out _));
	}

	private async Task<Result<AuthorizedGrant, OidcError>> RedeemWithRedirectUri(
		string? authorizedRedirectUri,
		string? requestedRedirectUri,
		bool pkce = false,
		bool namedNone = false)
	{
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest
		{
			Code = "abc",
			RedirectUri = requestedRedirectUri is null ? null : new Uri(requestedRedirectUri),
			CodeVerifier = pkce ? "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" : null,
		};

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)
					{
						RedirectUri = authorizedRedirectUri is null ? null : new Uri(authorizedRedirectUri),
						ClientNamedNoRedirectUri = namedNone,
						CodeChallenge = pkce ? "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" : null,
						CodeChallengeMethod = pkce ? CodeChallengeMethods.S256 : null,
					}));

		return await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);
	}

	/// <summary>
	/// A plain verifier, and so a plain challenge, of the syntax OAuth 2.1 section 4.1.1 gives both.
	/// </summary>
	private const string PlainVerifier = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJ";

	private async Task<Result<AuthorizedGrant, OidcError>> PkceTest(string codeChallengeMethod, string codeChallenge, string? codeVerifier)
	{
		// arrange
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest { Code = "abc", CodeVerifier = codeVerifier };

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)
					{
						CodeChallenge = codeChallenge,
						CodeChallengeMethod = codeChallengeMethod,
					}));

		// act
		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);
		return result;
	}
}
