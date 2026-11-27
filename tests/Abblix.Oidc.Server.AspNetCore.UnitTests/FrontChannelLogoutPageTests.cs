// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Features.LogoutNotification;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// The policy both transport adapters send with the front-channel logout page.
/// </summary>
public class FrontChannelLogoutPageTests
{
    /// <summary>
    /// The page runs only its own nonce-marked script and style, frames only the clients' origins, and is framed by
    /// nobody.
    /// </summary>
    [Fact]
    public void ThePolicy_NamesTheNonceAndTheFramedOrigins_AndDeniesEveryAncestor()
    {
        var response = new FrontChannelLogoutResponse(
            HtmlContent: "<html></html>",
            Nonce: "testNonce123",
            FrameSources: ["https://app1.example.com", "https://app2.example.com"]);

        Assert.Equal(
            "default-src 'none'; script-src 'nonce-testNonce123'; style-src 'nonce-testNonce123'; " +
            "frame-src https://app1.example.com https://app2.example.com; frame-ancestors 'none'",
            FrontChannelLogoutPage.ContentSecurityPolicy(response));
    }
}
