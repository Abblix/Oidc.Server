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
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Client.UnitTests.AspNetCore;

/// <summary>
/// What the endpoint answers a provider, and what it lets through to the host.
/// </summary>
public class BackChannelLogoutEndpointTests
{
    private const string Issuer = "https://provider.example.com";

    /// <summary>
    /// Accepts one token and refuses everything else, so a test says which case it is exercising by the
    /// token it sends.
    /// </summary>
    private sealed class StubLogoutTokenValidator(string acceptedToken) : ILogoutTokenValidator
    {
        public Task<LogoutNotification> ValidateAsync(
            string logoutToken, CancellationToken cancellationToken = default)
            => string.Equals(logoutToken, acceptedToken, StringComparison.Ordinal)
                ? Task.FromResult(new LogoutNotification(Issuer, "the-subject", null, "the-token-id"))
                : throw new LogoutTokenValidationException("refused by the stub");
    }

    private static DefaultHttpContext PostOf(params (string Name, string Value)[] form)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ILogoutTokenValidator>(new StubLogoutTokenValidator("the-valid-token"));

        // Executing an IResult asks the container for a logger, which every real host has.
        services.AddLogging();

        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(
            form.ToDictionary(entry => entry.Name, entry => new StringValues(entry.Value)));

        return context;
    }

    private static async Task<(int StatusCode, string? CacheControl, LogoutNotification? Handled)> CallAsync(
        DefaultHttpContext context)
    {
        LogoutNotification? handled = null;

        var result = await BackChannelLogoutEndpoint.HandleAsync(
            context.Request,
            (notification, _) =>
            {
                handled = notification;
                return Task.CompletedTask;
            },
            TestContext.Current.CancellationToken);

        await result.ExecuteAsync(context);

        return (context.Response.StatusCode, context.Response.Headers.CacheControl, handled);
    }

    /// <summary>
    /// A valid token ends the sessions it names and is answered 200, which section 2.8 requires: "If the
    /// logout succeeded, the RP MUST respond with HTTP 200 OK."
    /// </summary>
    [Fact]
    public async Task AValidTokenLogsOutAndAnswers200()
    {
        var (status, _, handled) = await CallAsync(
            PostOf((BackChannelLogoutEndpoint.LogoutTokenParameter, "the-valid-token")));

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.NotNull(handled);
        Assert.Equal("the-subject", handled.Subject);
    }

    /// <summary>
    /// Section 2.8: "The RP's response SHOULD include the Cache-Control HTTP response header field with a
    /// no-store value, keeping the response from being cached to prevent cached responses from interfering
    /// with future logout requests."
    /// </summary>
    [Fact]
    public async Task TheAnswerIsNotCacheable()
    {
        var (_, cacheControl, _) = await CallAsync(
            PostOf((BackChannelLogoutEndpoint.LogoutTokenParameter, "the-valid-token")));

        Assert.Equal("no-store", cacheControl);
    }

    /// <summary>
    /// A token that fails validation is answered 400 and nothing is logged out. Section 2.6: "If any of the
    /// validation steps fails, reject the Logout Token and return an HTTP 400 Bad Request error."
    /// </summary>
    [Fact]
    public async Task ARefusedTokenAnswers400AndLogsNobodyOut()
    {
        var (status, _, handled) = await CallAsync(
            PostOf((BackChannelLogoutEndpoint.LogoutTokenParameter, "a-forged-token")));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Null(handled);
    }

    /// <summary>
    /// The refusal is not cacheable either. A cached 400 would go on answering for a token that was only
    /// invalid the first time, which is the interference the header exists to prevent.
    /// </summary>
    [Fact]
    public async Task TheRefusalIsNotCacheableEither()
    {
        var (_, cacheControl, _) = await CallAsync(
            PostOf((BackChannelLogoutEndpoint.LogoutTokenParameter, "a-forged-token")));

        Assert.Equal("no-store", cacheControl);
    }

    /// <summary>
    /// A request carrying no token at all is refused before anything is resolved.
    /// </summary>
    [Fact]
    public async Task ARequestWithoutATokenIsRefused()
    {
        var (status, _, handled) = await CallAsync(PostOf(("something_else", "value")));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Null(handled);
    }

    /// <summary>
    /// Section 2.5 describes an HTTP POST carrying a form. A GET is not that request, whatever it carries in
    /// its query, and is refused rather than served from a query string.
    /// </summary>
    [Fact]
    public async Task AGetIsRefused()
    {
        var context = PostOf((BackChannelLogoutEndpoint.LogoutTokenParameter, "the-valid-token"));
        context.Request.Method = HttpMethods.Get;

        var (status, _, handled) = await CallAsync(context);

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Null(handled);
    }
}
