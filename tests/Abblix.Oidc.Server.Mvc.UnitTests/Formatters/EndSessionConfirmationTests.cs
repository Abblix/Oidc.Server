// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Where a logout the end user has to confirm sends the browser: to the tenant's confirmation page when it names one,
/// a relative one resolved as the tenant's other pages are, and otherwise nowhere, the answer carrying the issued value
/// for a page of the host's own.
/// </summary>
public class EndSessionConfirmationTests
{
    private const string Issued = "issued-confirmation";
    private const string TenantBase = "https://auth.example.com/acme";

    private static readonly EndSessionRequest Request = new() { ClientId = "the-client", State = "the-state" };

    /// <summary>
    /// A relative page is resolved by the adapter's resolver, an absolute one is used as it is, and the redirect
    /// carries the request and the issued value, with no referrer.
    /// </summary>
    [Theory]
    [InlineData("/logout-confirmation", TenantBase + "/logout-confirmation")]
    [InlineData("https://pages.example.com/confirm", "https://pages.example.com/confirm")]
    public async Task ALogoutToConfirm_IsSentToTheTenantsPage(string page, string expected)
    {
        var formatter = Formatter(new Uri(page, UriKind.RelativeOrAbsolute));

        var result = await formatter.FormatResponseAsync(Request, new ConfirmationRequired(Issued));
        var context = new ActionContext(new DefaultHttpContext(), new RouteData(), new ActionDescriptor());
        await result.ExecuteResultAsync(context);
        var sent = context.HttpContext.Response;

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
        var result = await Formatter(page: null).FormatResponseAsync(Request, new ConfirmationRequired(Issued));

        var refused = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ConfirmationRequiredResponse>(refused.Value);
        Assert.Equal(ErrorCodes.ConfirmationRequired, body.Error);
        Assert.Equal(Issued, body.Confirmation);
    }

    private static EndSessionResponseFormatter Formatter(Uri? page)
        => new(
            new NoFrontChannelPage(),
            new ServedBy(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(TenantBase),
                LogoutConfirmationUri = page,
            }),
            new UnderTheTenant());

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

    /// <summary>Resolves a relative page under the tenant's base, as the request's own address would.</summary>
    private sealed class UnderTheTenant : IUriResolver
    {
        public Uri Content(string path) => new(TenantBase + path);

        public Uri Action(string actionName, string controllerName, object? routeValues = null)
            => throw new NotSupportedException();
    }

    private sealed class NoFrontChannelPage : IFrontChannelLogoutService
    {
        public FrontChannelLogoutResponse GetFrontChannelLogoutResponse(
            Uri? postLogoutRedirectUri, IList<Uri> frontChannelLogoutUris)
            => throw new NotSupportedException();
    }
}
