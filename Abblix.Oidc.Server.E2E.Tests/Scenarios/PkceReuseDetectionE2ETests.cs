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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the RFC 9700 Section 2.1.1 constant-value detection against the real authorization
/// endpoint and the real token store: with detection enabled, a client that reuses a PKCE code_challenge it
/// already spent on an issued authorization code is rejected on its next authorization request. Detection is
/// opt-in and off in the default test host, so this test builds an isolated host with it turned on rather than
/// flipping it on for the whole suite.
/// </summary>
public class PkceReuseDetectionE2ETests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Reusing_a_code_challenge_across_authorizations_is_rejected()
    {
        // A host with reuse detection turned on (off in the shared default host).
        using var detectingHost = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.PkceAndNonceReuseDetectionInterval = TimeSpan.FromMinutes(5)))));

        var client = detectingHost.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var (_, codeChallenge) = GeneratePkcePair();

        // The first authorization completes and issues an authorization code, which records the code_challenge.
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, AuthorizeParameters(codeChallenge));
        Assert.False(string.IsNullOrEmpty(code));

        // A second authorization from the same client reusing the same code_challenge is rejected — the value
        // must be transaction-specific (RFC 9700 Section 2.1.1). State and nonce are fresh, so only the
        // repeated code_challenge triggers the rejection.
        var error = await AuthorizeAndExtractErrorAsync(client, discovery, AuthorizeParameters(codeChallenge));
        Assert.Equal(ErrorCodes.InvalidRequest, error);
    }

    private static Dictionary<string, string> AuthorizeParameters(string codeChallenge) => new()
    {
        [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
        [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
        [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
        [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
        [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
        [AuthorizationRequest.Parameters.CodeChallenge] = codeChallenge,
        [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
    };
}
