// Abblix OIDC Server Library
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

using System.Threading.Tasks;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.ClientAuthentication;

public class AuthorizationHeaderAdapterTests
{
    [Theory]
    [InlineData("id", "secret")]
    [InlineData("id", "secret:2")]
    public async Task BasicAuthorizationHeaderTest(string id, string secret)
    {
        // var clientAuthenticator = new Mock<IClientSecretAuthenticator>(MockBehavior.Strict);
        // var clientInfo = new ClientInfo();
        // clientAuthenticator.Setup(_ => _.TryAuthenticateAsync(id, secret)).ReturnsAsync(clientInfo);
        //
        // var parameter = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{id}:{secret}"));
        // var request = new TokenRequest { AuthorizationHeader = new AuthenticationHeaderValue("Basic", parameter) };
        //
        // var adapter = new ClientSecretBasicAuthenticator(clientAuthenticator.Object);
        // var result = await adapter.TryAuthenticateClientAsync(request);
        // Assert.Equal(clientInfo, result);
    }
}
