﻿// Abblix OIDC Server Library
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
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
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
	private readonly Mock<IParameterValidator> _parameterValidator;
	private readonly AuthorizationCodeGrantHandler _handler;

	public AuthorizationCodeGrantHandlerTests()
	{
		_authCodeService = new Mock<IAuthorizationCodeService>(MockBehavior.Strict);
		_parameterValidator = new Mock<IParameterValidator>(MockBehavior.Strict);

		_handler = new AuthorizationCodeGrantHandler(
			_parameterValidator.Object,
			_authCodeService.Object);
	}

	[Theory]
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
	[InlineData(CodeChallengeMethods.Plain, "qwerty", "qwerty")]
	public async Task PkceSuccessfulChallengeTest(string codeChallengeMethod, string codeChallenge, string codeVerifier)
	{
		var result = await PkceTest(codeChallengeMethod, codeChallenge, codeVerifier);

		// assert
		Assert.IsType<AuthorizedGrantResult>(result);
	}

	[Theory]
	[InlineData(CodeChallengeMethods.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "abc")]
	[InlineData(CodeChallengeMethods.S256, "qwerty", null)]
	[InlineData(CodeChallengeMethods.Plain, "qwerty", "asdfgh")]
	[InlineData(CodeChallengeMethods.Plain, "qwerty", null)]
	public async Task PkceFailureChallengeTest(string codeChallengeMethod, string codeChallenge, string codeVerifier)
	{
		var result = await PkceTest(codeChallengeMethod, codeChallenge, codeVerifier);

		// assert
		Assert.IsType<InvalidGrantResult>(result);
		var invalidGrantResult = (InvalidGrantResult)result;

		Assert.Equal(ErrorCodes.InvalidGrant, invalidGrantResult.Error);
	}

	private async Task<GrantAuthorizationResult> PkceTest(string codeChallengeMethod, string codeChallenge, string codeVerifier)
	{
		// arrange
		var clientInfo = new ClientInfo("client1");
		var tokenRequest = new TokenRequest { Code = "abc", CodeVerifier = codeVerifier };
		_parameterValidator.Setup(v => v.Required(tokenRequest.Code, "Code"));

		_authCodeService
			.Setup(s => s.AuthorizeByCodeAsync(tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrantResult(
					new AuthSession("123", "session1", DateTimeOffset.UtcNow, "ip"),
					Context: new AuthorizationContext(clientInfo.ClientId, [Scopes.OpenId], null)
					{
						CodeChallenge = codeChallenge,
						CodeChallengeMethod = codeChallengeMethod,
					}));

		// act
		var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);
		return result;
	}
}
