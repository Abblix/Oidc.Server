// Abblix OIDC Client Library
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

using System.Web;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.PasswordGrant;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Abblix.Oidc.Client.UnitTests.Features.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.PasswordGrant;

/// <summary>
/// The grant RFC 9700 section 2.4 forbids, and the registration that keeps it out of reach until a host asks
/// for it by name.
/// </summary>
public class PasswordGrantTests
{
    private const string Issuer = "https://provider.example.com";

    private const string SuccessBody = """
                                       {
                                         "access_token": "the-access-token",
                                         "token_type": "Bearer",
                                         "refresh_token": "the-refresh-token"
                                       }
                                       """;

    private static IPasswordGrantService CreateService(RecordingHttpMessageHandler handler)
        => new PasswordGrantService(
            new ConfiguredMetadataProvider(new ProviderMetadata
            {
                Issuer = Issuer,
                TokenEndpoint = $"{Issuer}/token",
            }),
            new StubHttpClientFactory(handler),
            new ClientCredentialsPresenter(
                Options.Create(new OidcClientOptions { ClientId = "test-client" }),
                Options.Create(new ClientAuthenticationOptions { Method = ClientAuthenticationMethods.None })));

    private static Dictionary<string, string> FormOf(string body)
    {
        var parsed = HttpUtility.ParseQueryString(body);
        return parsed.AllKeys
            .Where(key => key is not null)
            .ToDictionary(key => key!, key => parsed[key]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// The credentials travel under the names RFC 6749 section 4.3.2 gives them, with the scopes asked for.
    /// </summary>
    [Fact]
    public async Task TheCredentialsAreSentUnderTheGrant()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        var response = await CreateService(handler).RequestTokensAsync(
            "alice", "correct-horse-battery-staple", ["openid", "profile"],
            TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal(GrantTypes.Password, form["grant_type"]);
        Assert.Equal("alice", form["username"]);
        Assert.Equal("correct-horse-battery-staple", form["password"]);
        Assert.Equal("openid profile", form["scope"]);

        // The one mercy of this grant: with a refresh token the application need not keep the password to
        // stay signed in.
        Assert.Equal("the-refresh-token", response.RefreshToken);
    }

    /// <summary>
    /// Asking for nothing in particular omits <c>scope</c> rather than sending it empty.
    /// </summary>
    [Fact]
    public async Task WithoutScopesTheParameterIsOmitted()
    {
        var handler = new RecordingHttpMessageHandler(SuccessBody);

        await CreateService(handler).RequestTokensAsync(
            "alice", "correct-horse-battery-staple",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(FormOf(handler.LastRequestBody!).ContainsKey("scope"));
    }

    /// <summary>
    /// A host that registered the ordinary token requests cannot reach this grant, and one that named it can.
    /// </summary>
    /// <remarks>
    /// This is the whole of what the prohibition buys, so it is asserted rather than left to the reader of a
    /// doc comment: the grant is absent from the container until <c>AddResourceOwnerPasswordCredentials</c>
    /// appears in the host, which also makes every application that opted in findable by one search.
    /// </remarks>
    [Fact]
    public void TheGrantIsAbsentUntilTheHostNamesIt()
    {
        var withoutIt = new ServiceCollection()
            .AddOidcClientCore(options => options.ClientId = "test-client")
            .AddClientAuthentication(options => options.Method = ClientAuthenticationMethods.None)
            .AddTokenRequests()
            .BuildServiceProvider();

        Assert.Null(withoutIt.GetService<IPasswordGrantService>());

        var withIt = new ServiceCollection()
            .AddOidcClientCore(options => options.ClientId = "test-client")
            .AddClientAuthentication(options => options.Method = ClientAuthenticationMethods.None)
            .AddTokenRequests()
            .AddResourceOwnerPasswordCredentials()
            .BuildServiceProvider();

        Assert.NotNull(withIt.GetService<IPasswordGrantService>());
    }
}
