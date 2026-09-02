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

using Abblix.Oidc.Client.AspNetCore;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using AuthorizationFlow = Abblix.Oidc.Client.Features.Authorization.Requests.AuthorizationFlow;
using AuthorizationRequestOptions = Abblix.Oidc.Client.Features.Authorization.Requests.AuthorizationRequestOptions;
using ResponseModes = Abblix.Oidc.Client.Features.Authorization.Requests.ResponseModes;
using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Client.UnitTests.AspNetCore;

/// <summary>
/// Handling a callback straight from an <see cref="HttpRequest"/>: the parameters are read from wherever
/// the response mode put them, then run through the very same handler any other host would use.
/// </summary>
public class AuthorizationResponseHandlerExtensionsTests
{
    private const string Provider = "https://provider.example.com";
    private const string State = "the-state";

    private sealed class StubMetadataProvider : IProviderMetadataProvider
    {
        public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new ProviderMetadata
            {
                Issuer = Provider,
                AuthorizationResponseIssParameterSupported = true,
            });
    }

    private static (IAuthorizationResponseHandler Handler, IAuthorizationStateStore Store, IServiceProvider Services)
        Create(Action<AuthorizationRequestOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider());
        services.AddAuthorizationResponseHandling();
        if (configure is not null)
            services.Configure(configure);

        var provider = services.BuildServiceProvider();
        return (
            provider.GetRequiredService<IAuthorizationResponseHandler>(),
            provider.GetRequiredService<IAuthorizationStateStore>(),
            provider);
    }

    private static async Task StoreLogin(IAuthorizationStateStore store)
        => await store.StoreAsync(
            new AuthorizationContext
            {
                State = State,
                Nonce = "the-nonce",
                CodeVerifier = "the-verifier",
                ReturnUri = "/orders",
                Issuer = Provider,
                RedirectUri = "https://client.example.com/signin-oidc",
            },
            TestContext.Current.CancellationToken);

    private static DefaultHttpContext GetWithQuery(params (string Name, string Value)[] parameters)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Query = new QueryCollection(
            parameters.ToDictionary(p => p.Name, p => new StringValues(p.Value)));
        return context;
    }

    /// <summary>
    /// The code-flow response arrives in the query, and the whole trust pipeline runs from the request.
    /// </summary>
    [Fact]
    public async Task ReadsACodeResponseFromTheQuery()
    {
        var (handler, store, _) = Create();
        await StoreLogin(store);

        var request = GetWithQuery(
            ("code", "the-code"), ("state", State), ("iss", Provider)).Request;

        var result = await handler.HandleAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("the-code", result.Code);
        Assert.Equal("the-verifier", result.Context.CodeVerifier);
    }

    /// <summary>
    /// A form_post response arrives in the posted form instead, and is read the same way.
    /// </summary>
    [Fact]
    public async Task ReadsACodeResponseFromAPostedForm()
    {
        var (handler, store, _) = Create();
        await StoreLogin(store);

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(new()
        {
            ["code"] = "the-code",
            ["state"] = State,
            ["iss"] = Provider,
        });

        var result = await handler.HandleAsync(context.Request, TestContext.Current.CancellationToken);

        Assert.Equal("the-code", result.Code);
    }

    /// <summary>
    /// A parameter the query repeats reaches the handler as two values and is refused there, not silently
    /// resolved to one in this layer (RFC 6749 section 3.1).
    /// </summary>
    [Fact]
    public async Task ARepeatedQueryParameter_ReachesTheHandlerAndIsRefused()
    {
        var (handler, store, _) = Create();
        await StoreLogin(store);

        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Query = new QueryCollection(new Dictionary<string, StringValues>
        {
            ["code"] = new StringValues(["one-code", "another-code"]),
            ["state"] = State,
        });

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(context.Request, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A provider error carried in the query surfaces as the handler's typed refusal with the error code.
    /// </summary>
    [Fact]
    public async Task ReadsAnErrorResponseFromTheQuery()
    {
        var (handler, store, _) = Create();
        await StoreLogin(store);

        var request = GetWithQuery(
            ("error", "access_denied"), ("state", State), ("iss", Provider)).Request;

        var error = await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal("access_denied", error.Error);
    }

    /// <summary>
    /// A token-returning flow that asked for a form post and receives a query GET instead is refused.
    /// Multiple Response Type Encoding Practices section 5 forbids the query encoding for such a response,
    /// so this is a transport the provider was not allowed to use - a downgrade, not an alternative.
    /// </summary>
    [Fact]
    public async Task ATokenResponseArrivingInTheQuery_IsRefused()
    {
        var (handler, store, services) = Create(options =>
        {
            options.Flow = AuthorizationFlow.CodeIdToken;
            options.FrontChannelTokensAccepted = true;
            options.ResponseMode = ResponseModes.FormPost;
        });
        await StoreLogin(store);

        var context = GetWithQuery(
            ("code", "the-code"), ("id_token", "the-id-token"), ("state", State), ("iss", Provider));
        context.RequestServices = services;

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(context.Request, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// And an empty GET, which is what a fragment-delivered response looks like once the browser has
    /// stripped the fragment, is refused by the same check rather than read as a provider that said
    /// nothing.
    /// </summary>
    [Fact]
    public async Task AnEmptyCallbackForATokenFlow_IsRefused()
    {
        var (handler, store, services) = Create(options =>
        {
            options.Flow = AuthorizationFlow.IdToken;
            options.FrontChannelTokensAccepted = true;
            options.ResponseMode = ResponseModes.FormPost;
        });
        await StoreLogin(store);

        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = HttpMethods.Get;

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(context.Request, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The code flow is untouched by the transport check: its response belongs in the query, and nothing
    /// about it was asked to arrive as a form.
    /// </summary>
    [Fact]
    public async Task ACodeResponseInTheQuery_IsStillRead()
    {
        var (handler, store, services) = Create();
        await StoreLogin(store);

        var context = GetWithQuery(("code", "the-code"), ("state", State), ("iss", Provider));
        context.RequestServices = services;

        var result = await handler.HandleAsync(context.Request, TestContext.Current.CancellationToken);

        Assert.Equal("the-code", result.Code);
    }
}
