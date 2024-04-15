// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;

using Moq;

using Xunit;


namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public class AuthorizationCodeGrantHandlerTests
{
	private Mock<IAuthorizationCodeService> _authCodeService;
	private Mock<IParameterValidator> _parameterValidator;
	private AuthorizationCodeGrantHandler _handler;

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
		_parameterValidator.Setup(_ => _.Required(tokenRequest.Code, "Code"));

		_authCodeService
			.Setup(_ => _.AuthorizeByCodeAsync(tokenRequest.Code))
			.ReturnsAsync(
				new AuthorizedGrantResult(
					new AuthSession("123", "session1", DateTimeOffset.UtcNow),
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
