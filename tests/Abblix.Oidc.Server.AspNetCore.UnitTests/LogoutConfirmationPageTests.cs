// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Reflection;
using System.Web;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// The address of the confirmation page carries everything the page sends back to the end-session endpoint, so the
/// request the end user answers is the request they were asked about.
/// </summary>
public class LogoutConfirmationPageTests
{
    private static readonly Uri Page = new("https://auth.example.com/logout-confirmation?theme=dark");

    /// <summary>
    /// Every parameter of a logout request reaches the page, the issued value in place of any the request named, and
    /// whatever query the page's own address has stays. A parameter the request model gains and this address leaves
    /// out would be lost on the way back, and the answered request would differ from the one asked about.
    /// </summary>
    [Fact]
    public void Address_CarriesEveryParameterOfTheRequestAndTheIssuedValue()
    {
        var request = new EndSessionRequest
        {
            IdTokenHint = "the-hint",
            LogoutHint = "end-user@example.com",
            ClientId = "the-client",
            PostLogoutRedirectUri = new Uri("https://client.example.com/after-logout?x=1"),
            State = "the-state",
            UiLocales = [new CultureInfo("fr-CA"), new CultureInfo("en")],
            Confirmation = "made-up-by-the-caller",
        };

        var carried = HttpUtility.ParseQueryString(new Uri(LogoutConfirmationPage.Address(Page, request, "issued")).Query);

        var names = typeof(EndSessionRequest.Parameters)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(field => (string)field.GetValue(null)!)
            .Append("theme");
        Assert.Equal(names.Order(), carried.AllKeys.Order());

        Assert.Equal("the-hint", carried[EndSessionRequest.Parameters.IdTokenHint]);
        Assert.Equal("end-user@example.com", carried[EndSessionRequest.Parameters.LogoutHint]);
        Assert.Equal("the-client", carried[EndSessionRequest.Parameters.ClientId]);
        Assert.Equal("https://client.example.com/after-logout?x=1", carried[EndSessionRequest.Parameters.PostLogoutRedirectUri]);
        Assert.Equal("the-state", carried[EndSessionRequest.Parameters.State]);
        Assert.Equal("fr-CA en", carried[EndSessionRequest.Parameters.UiLocales]);
        Assert.Equal("issued", carried[EndSessionRequest.Parameters.Confirmation]);
        Assert.Equal("dark", carried["theme"]);
    }

    /// <summary>
    /// A parameter the request did not carry is not sent as an empty one, which the endpoint would read as stated.
    /// </summary>
    [Fact]
    public void Address_LeavesOutWhatTheRequestDidNotCarry()
    {
        var carried = HttpUtility.ParseQueryString(
            new Uri(LogoutConfirmationPage.Address(Page, new EndSessionRequest(), "issued")).Query);

        Assert.Equal(["theme", EndSessionRequest.Parameters.Confirmation], carried.AllKeys);
    }
}
