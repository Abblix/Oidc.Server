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
	[InlineData(CodeChallengeMethods.Plain, "qwerty", "qwerty")]
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
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "abc")]
	[InlineData(CodeChallengeMethods.S256, "qwerty", null)]
	[InlineData(CodeChallengeMethods.Plain, "qwerty", "asdfgh")]
	[InlineData(CodeChallengeMethods.Plain, "qwerty", null)]
	// RFC 7636 section 4.6: the plain verifier is compared byte-for-byte, so a case flip must fail. This case
	// would have passed under the previous case-insensitive comparison - it locks the ordinal comparison in.
	[InlineData(CodeChallengeMethods.Plain, "qwerty", "QWERTY")]
	public async Task PkceFailureChallengeTest(string codeChallengeMethod, string codeChallenge, string? codeVerifier)
	{
		var result = await PkceTest(codeChallengeMethod, codeChallenge, codeVerifier);

		// assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// RFC 9700 (OAuth 2.0 Security BCP) section 2.1.1: presenting a code_verifier for an authorization code that
	/// was issued without a code_challenge signals a PKCE downgrade / code-injection attempt. The verifier
	/// must be rejected (invalid_grant) rather than silently ignored while tokens are issued.
	/// </summary>
	[Fact]
	public async Task AuthorizeAsync_CodeVerifierWithoutCodeChallenge_ReturnsInvalidGrant()
	{
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest { Code = "abc", CodeVerifier = "unexpected-verifier" };

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)));

		var result = await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
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
	[InlineData("https://client.example.com/callback", null)]
	[InlineData(null, "https://client.example.com/callback")]
	public async Task ARedirectUriOtherThanTheAuthorizationRequests_ReturnsInvalidGrant(
		string? authorizedRedirectUri,
		string? requestedRedirectUri)
	{
		var result = await RedeemWithRedirectUri(authorizedRedirectUri, requestedRedirectUri);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// The redirect URI of the authorization request, sent again, or none on either side, redeems the code.
	/// </summary>
	[Theory]
	[InlineData("https://client.example.com/callback", "https://client.example.com/callback")]
	[InlineData(null, null)]
	public async Task TheAuthorizationRequestsRedirectUri_RedeemsTheCode(
		string? authorizedRedirectUri,
		string? requestedRedirectUri)
	{
		var result = await RedeemWithRedirectUri(authorizedRedirectUri, requestedRedirectUri);

		Assert.True(result.TryGetSuccess(out _));
	}

	private async Task<Result<AuthorizedGrant, OidcError>> RedeemWithRedirectUri(
		string? authorizedRedirectUri,
		string? requestedRedirectUri)
	{
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest
		{
			Code = "abc",
			RedirectUri = requestedRedirectUri is null ? null : new Uri(requestedRedirectUri),
		};

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(TestTenant.Matched, tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrant(
					new AuthSession("123", "session1", TimeProvider.System.GetUtcNow(), "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)
					{
						RedirectUri = authorizedRedirectUri is null ? null : new Uri(authorizedRedirectUri),
					}));

		return await _handler.AuthorizeAsync(SingleIssuer.Tenant, tokenRequest, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);
	}

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
