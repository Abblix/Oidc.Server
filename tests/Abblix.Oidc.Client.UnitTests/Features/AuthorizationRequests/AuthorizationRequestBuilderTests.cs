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
using Abblix.Oidc.Client.Features.AuthorizationRequests;
using Abblix.Oidc.Client.Features.AuthorizationState;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Pkce;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.AuthorizationRequests;

/// <summary>
/// Tests for <see cref="AuthorizationRequestBuilder"/>.
/// </summary>
public class AuthorizationRequestBuilderTests
{
    private const string Issuer = "https://provider.example.com";
    private const string RedirectUri = "https://client.example.com/signin-oidc";

    private static readonly Uri ReturnUri = new("https://client.example.com/orders", UriKind.Absolute);

    private static ProviderMetadata Metadata(
        string? authorizationEndpoint = $"{Issuer}/authorize",
        IReadOnlyList<string>? codeChallengeMethods = null) => new()
    {
        Issuer = Issuer,
        AuthorizationEndpoint = authorizationEndpoint,
        CodeChallengeMethodsSupported = codeChallengeMethods,
    };

    private static AuthorizationRequestBuilder CreateBuilder(
        ProviderMetadata metadata,
        IAuthorizationStateStore stateStore,
        Action<AuthorizationRequestOptions>? configure = null)
    {
        var metadataProvider = new ConfiguredMetadataProvider(metadata);

        var options = new AuthorizationRequestOptions { RedirectUri = new Uri(RedirectUri) };
        configure?.Invoke(options);

        return new AuthorizationRequestBuilder(
            metadataProvider,
            new PkceProvider(metadataProvider),
            stateStore,
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(options));
    }

    private static InMemoryAuthorizationStateStore CreateStateStore(TimeProvider? timeProvider = null) => new(
        timeProvider ?? new FakeTimeProvider(),
        Options.Create(new AuthorizationStateOptions()));

    private static Dictionary<string, string> QueryOf(Uri uri)
    {
        var parsed = HttpUtility.ParseQueryString(uri.Query);
        return parsed.AllKeys
            .Where(key => key is not null)
            .ToDictionary(key => key!, key => parsed[key]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// The request carries what the authorization code flow needs, and the challenge is the SHA-256 one.
    /// </summary>
    [Fact]
    public async Task CarriesTheParametersOfTheCodeFlow()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.Equal("code", query[Parameters.ResponseType]);
        Assert.Equal("test-client", query[Parameters.ClientId]);
        Assert.Equal(RedirectUri, query[Parameters.RedirectUri]);
        Assert.Equal(CodeChallengeMethods.S256, query[Parameters.CodeChallengeMethod]);
        Assert.NotEmpty(query[Parameters.CodeChallenge]);
    }

    /// <summary>
    /// The values that tie a response back to its request are the ones put aside, so the callback can be
    /// checked against what was actually sent.
    /// </summary>
    [Fact]
    public async Task SendsTheStateAndNonceItPutAside()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var query = QueryOf(request.RequestUri);

        Assert.Equal(request.State.State, query[Parameters.State]);
        Assert.Equal(request.State.Nonce, query[Parameters.Nonce]);
        Assert.Equal(Issuer, request.State.Issuer);
        Assert.Equal(ReturnUri.ToString(), request.State.ReturnUri);
    }

    /// <summary>
    /// The code challenge sent is derived from the verifier kept, which is the whole point of PKCE: the two
    /// halves must belong to each other or the exchange cannot be proved.
    /// </summary>
    [Fact]
    public async Task TheChallengeSentMatchesTheVerifierKept()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var expectedChallenge = System.Buffers.Text.Base64Url.EncodeToString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.ASCII.GetBytes(request.State.CodeVerifier)));

        Assert.Equal(expectedChallenge, QueryOf(request.RequestUri)[Parameters.CodeChallenge]);
    }

    /// <summary>
    /// Two requests never share their opaque values, or one captured response could be passed off as the
    /// answer to another request.
    /// </summary>
    [Fact]
    public async Task EveryRequestGetsItsOwnValues()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore());

        var first = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);
        var second = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.NotEqual(first.State.State, second.State.State);
        Assert.NotEqual(first.State.Nonce, second.State.Nonce);
        Assert.NotEqual(first.State.CodeVerifier, second.State.CodeVerifier);
    }

    /// <summary>
    /// The state is stored before the address is handed out, so a callback can never arrive for a state that
    /// was not put aside yet.
    /// </summary>
    [Fact]
    public async Task StoresTheStateBeforeHandingOutTheAddress()
    {
        var store = CreateStateStore();

        var request = await CreateBuilder(Metadata(), store)
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var stored = await store.TakeAsync(request.State.State, TestContext.Current.CancellationToken);
        Assert.NotNull(stored);
        Assert.Equal(request.State.CodeVerifier, stored.CodeVerifier);
    }

    /// <summary>
    /// A provider that advertises only the weaker transformation gets a refusal, not a downgrade. Falling
    /// back to `plain` would leave the request looking protected while anyone who read it holds the verifier.
    /// </summary>
    [Fact]
    public async Task RefusesToDowngradeWhenTheProviderOffersOnlyPlain()
    {
        var builder = CreateBuilder(
            Metadata(codeChallengeMethods: [CodeChallengeMethods.Plain]), CreateStateStore());

        var exception = await Assert.ThrowsAsync<PkceException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));

        Assert.Contains(CodeChallengeMethods.S256, exception.Message);
    }

    /// <summary>
    /// A provider that advertises nothing is given the benefit of the doubt: the member is optional, and a
    /// request it cannot honour fails at the provider rather than weakening anything here.
    /// </summary>
    [Fact]
    public async Task ProceedsWhenTheProviderAdvertisesNoMethods()
    {
        var request = await CreateBuilder(Metadata(), CreateStateStore())
            .CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal(CodeChallengeMethods.S256, QueryOf(request.RequestUri)[Parameters.CodeChallengeMethod]);
    }

    /// <summary>
    /// Every named resource is sent, because RFC 8707 lets the parameter repeat and each occurrence narrows
    /// the token further. Keeping only the last would silently widen what the token is good for.
    /// </summary>
    [Fact]
    public async Task SendsEveryNamedResource()
    {
        var builder = CreateBuilder(Metadata(), CreateStateStore(), options => options.Resources =
        [
            new Uri("https://api.example.com/orders"),
            new Uri("https://api.example.com/billing"),
        ]);

        var request = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        var resources = HttpUtility.ParseQueryString(request.RequestUri.Query).GetValues(Parameters.Resource);
        Assert.NotNull(resources);
        Assert.Equal(
            ["https://api.example.com/orders", "https://api.example.com/billing"],
            resources);
    }

    /// <summary>
    /// Parameters the provider already carries on its authorization endpoint survive, since dropping them
    /// would break a provider that publishes an endpoint with a query of its own.
    /// </summary>
    [Fact]
    public async Task KeepsParametersTheEndpointAlreadyCarries()
    {
        var builder = CreateBuilder(
            Metadata(authorizationEndpoint: $"{Issuer}/authorize?tenant=acme"), CreateStateStore());

        var request = await builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken);

        Assert.Equal("acme", QueryOf(request.RequestUri)["tenant"]);
    }

    /// <summary>
    /// A provider naming no authorization endpoint leaves nowhere to send the user, and says so.
    /// </summary>
    [Fact]
    public async Task FailsWhenTheProviderNamesNoAuthorizationEndpoint()
    {
        var builder = CreateBuilder(Metadata(authorizationEndpoint: null), CreateStateStore());

        await Assert.ThrowsAsync<AuthorizationRequestException>(
            () => builder.CreateAsync(ReturnUri, TestContext.Current.CancellationToken));
    }
}
