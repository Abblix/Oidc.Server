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

using System;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using HashAlgorithm = Abblix.Oidc.Server.Features.Hashing.HashAlgorithm;

namespace Abblix.Oidc.Server.UnitTests.ClientAuthentication;

public class AuthorizationHeaderAdapterTests
{
    [Theory]
    [InlineData("id", "secret")]
    [InlineData("id", "secret:2")]
    public async Task BasicAuthorizationHeaderTest(string id, string secret)
    {
        var hashService = new Mock<IHashService>(MockBehavior.Strict);
        var secretHashCode = Encoding.ASCII.GetBytes(secret);
        hashService.Setup(s => s.Sha(HashAlgorithm.Sha512, secret)).Returns(secretHashCode);

        var clientInfo = new ClientInfo(id)
        {
            ClientSecrets = [new ClientSecret { Sha512Hash = secretHashCode }],
        };

        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clientInfoProvider.Setup(p => p.TryFindClientAsync(id)).ReturnsAsync(clientInfo);

        var parameter = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{id}:{secret}"));
        var request = new ClientRequest { AuthorizationHeader = new AuthenticationHeaderValue("Basic", parameter) };

        var adapter = new ClientSecretBasicAuthenticator(
            new Mock<ILogger<ClientSecretBasicAuthenticator>>().Object,
            clientInfoProvider.Object,
            TimeProvider.System,
            hashService.Object);

        var result = await adapter.TryAuthenticateClientAsync(request);
        Assert.Equal(clientInfo, result);
    }
}
