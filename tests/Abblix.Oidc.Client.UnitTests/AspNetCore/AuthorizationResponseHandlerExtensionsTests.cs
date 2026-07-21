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

    private static (IAuthorizationResponseHandler Handler, IAuthorizationStateStore Store) Create()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProviderMetadataProvider>(new StubMetadataProvider());
        services.AddAuthorizationResponseHandling();

        var provider = services.BuildServiceProvider();
        return (
            provider.GetRequiredService<IAuthorizationResponseHandler>(),
            provider.GetRequiredService<IAuthorizationStateStore>());
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
        var (handler, store) = Create();
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
        var (handler, store) = Create();
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
        var (handler, store) = Create();
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
        var (handler, store) = Create();
        await StoreLogin(store);

        var request = GetWithQuery(
            ("error", "access_denied"), ("state", State), ("iss", Provider)).Request;

        var error = await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => handler.HandleAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal("access_denied", error.Error);
    }
}
