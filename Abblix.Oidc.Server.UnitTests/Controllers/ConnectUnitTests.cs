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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

using Moq;
using Xunit;


namespace Abblix.Oidc.Server.UnitTests.Controllers;

public class ConnectUnitTests
{
	private IAuthorizationRequestValidator _validator;
	private Mock<IClientInfoProvider> _clientInfoProvider;

	public ConnectUnitTests()
	{
		_clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);

		//_validator = new AuthorizationRequestValidator(
		//	new Mock<ILogger<AuthorizationRequestValidator>>().Object,
		//	_clientInfoProvider.Object);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("not-existing-id")]
	public async Task AuthorizeIncorrectClientIdTest(string clientId)
	{
		_clientInfoProvider.Setup(p => p.TryFindClientAsync(It.IsAny<string>())).ReturnsAsync((ClientInfo)null);

		var result = await _validator.ValidateAsync(new AuthorizationRequest { ClientId = clientId });
		Assert.IsType<AuthorizationRequestValidationError>(result);

		var error = (AuthorizationRequestValidationError)result;
		Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
		Assert.Equal("The client is not authorized", error.ErrorDescription);
	}

	[Theory]
	[InlineData("testClient")]
	public async Task AuthorizeCorrectClientIdTest(string clientId)
	{
		var redirectUri = new Uri("https://localhost/");
		var clientInfo = new ClientInfo("Client1")
		{
			RedirectUris = new[] { redirectUri },
			PkceRequired = false,
		};
		_clientInfoProvider.Setup(_ => _.TryFindClientAsync(clientId)).ReturnsAsync(clientInfo);

		var result = await _validator.ValidateAsync(
			new AuthorizationRequest
			{
				ClientId = clientId,
				RedirectUri = redirectUri,
				ResponseType = new[] { ResponseTypes.Code },
			});

		Assert.IsType<ValidAuthorizationRequest>(result);

		var validResult = (ValidAuthorizationRequest)result;
		Assert.Equal(clientInfo, validResult.ClientInfo);
		Assert.False(string.IsNullOrEmpty(validResult.ResponseMode));
	}
}
