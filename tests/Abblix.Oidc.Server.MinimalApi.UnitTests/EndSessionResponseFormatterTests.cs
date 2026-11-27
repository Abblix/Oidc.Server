// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// Where a logout the end user has to confirm sends the browser: to the tenant's confirmation page when it names one,
/// resolved under the tenant as its other pages are, and otherwise nowhere, the answer carrying the issued value for a
/// page of the host's own.
/// </summary>
public class EndSessionResponseFormatterTests
{
    private const string Issued = "issued-confirmation";

    private static readonly EndSessionRequest Request = new() { ClientId = "the-client", State = "the-state" };

    /// <summary>
    /// A relative page is resolved under the tenant the request is served at, an absolute one is used as it is, and
    /// the redirect carries the request and the issued value, with no referrer.
    /// </summary>
    [Theory]
    [InlineData("/logout-confirmation", "https://auth.example.com/acme/logout-confirmation")]
    [InlineData("https://pages.example.com/confirm", "https://pages.example.com/confirm")]
    public async Task ALogoutToConfirm_IsSentToTheTenantsPage(string page, string expected)
    {
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com/acme"),
            LogoutConfirmationUri = new Uri(page, UriKind.RelativeOrAbsolute),
        };

        var sent = await HttpResultRunner.RunAsync(await Formatter(tenant).FormatResponseAsync(
            Request, new ConfirmationRequired(Issued)));

        Assert.Equal(StatusCodes.Status303SeeOther, sent.StatusCode);
        var location = new Uri(sent.Headers.Location.ToString());
        Assert.Equal(expected, location.GetLeftPart(UriPartial.Path));

        var carried = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal(Issued, carried[EndSessionRequest.Parameters.Confirmation]);
        Assert.Equal("the-client", carried[EndSessionRequest.Parameters.ClientId]);
        Assert.Equal("the-state", carried[EndSessionRequest.Parameters.State]);
        Assert.Equal("no-referrer", sent.Headers["Referrer-Policy"].ToString());
    }

    /// <summary>
    /// A tenant naming no page gets the error a host's own page reads the issued value from.
    /// </summary>
    [Fact]
    public async Task WithoutAPage_TheAnswerCarriesTheIssuedValue()
    {
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };

        var sent = await HttpResultRunner.RunAsync(await Formatter(tenant).FormatResponseAsync(
            Request, new ConfirmationRequired(Issued)));

        Assert.Equal(StatusCodes.Status400BadRequest, sent.StatusCode);
        var body = JsonNode.Parse(sent.Body)!;
        Assert.Equal(ErrorCodes.ConfirmationRequired, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
        Assert.Equal(Issued, body[ConfirmationRequiredResponse.Parameters.Confirmation]!.GetValue<string>());
    }

    /// <summary>
    /// The page that frames the clients' front-channel logout addresses is itself framed by nobody (RFC 9700 section
    /// 4.16): its policy denies every ancestor beside naming the frames it loads, and X-Frame-Options covers user agents
    /// without frame-ancestors.
    /// </summary>
    [Fact]
    public async Task TheFrontChannelLogoutPage_IsFramedByNobody()
    {
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com/acme") };

        var sent = await HttpResultRunner.RunAsync(await Formatter(tenant, new FrontChannelPage()).FormatResponseAsync(
            Request, new EndSessionSuccess(null, [new Uri("https://client.example.com/front-channel-logout")])));

        Assert.Equal(StatusCodes.Status200OK, sent.StatusCode);
        var policy = sent.Headers[HeaderNames.ContentSecurityPolicy].ToString();
        Assert.Contains("frame-src https://client.example.com", policy);
        Assert.Contains("frame-ancestors 'none'", policy);
        Assert.Equal("DENY", sent.Headers[HeaderNames.XFrameOptions].ToString());
    }

    /// <summary>
    /// A formatter serving <paramref name="tenant"/> for a request that arrived under the tenant's issuer path.
    /// </summary>
    private static EndSessionResponseFormatter Formatter(
        TenantDefinition tenant,
        IFrontChannelLogoutService? frontChannelLogoutService = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = Uri.UriSchemeHttps;
        context.Request.Host = new HostString(tenant.Issuer.Host);
        context.Request.PathBase = tenant.Issuer.AbsolutePath;

        return new EndSessionResponseFormatter(
            frontChannelLogoutService ?? new NoFrontChannelPage(),
            new ServedBy(tenant),
            new HttpContextAccessor { HttpContext = context });
    }

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

    private sealed class NoFrontChannelPage : IFrontChannelLogoutService
    {
        public FrontChannelLogoutResponse GetFrontChannelLogoutResponse(
            Uri? postLogoutRedirectUri, IList<Uri> frontChannelLogoutUris)
            => throw new NotSupportedException();
    }

    private sealed class FrontChannelPage : IFrontChannelLogoutService
    {
        public FrontChannelLogoutResponse GetFrontChannelLogoutResponse(
            Uri? postLogoutRedirectUri, IList<Uri> frontChannelLogoutUris)
            => new("<html></html>", "the-nonce", ["https://client.example.com"]);
    }
}
