// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Mvc.Formatters;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Unit tests for <see cref="EndSessionResponseFormatter"/>.
/// </summary>
public class EndSessionResponseFormatterTests
{
    [Fact]
    public void GetContentSecurityPolicy_ReturnsCorrectValue()
    {
        // Arrange
        var response = new FrontChannelLogoutResponse(
            HtmlContent: "<html></html>",
            Nonce: "testNonce123",
            FrameSources: ["https://app1.example.com", "https://app2.example.com"]);

        // Act
        var csp = EndSessionResponseFormatter.GetContentSecurityPolicy(response);

        // Assert
        Assert.Equal(
            "default-src 'none'; script-src 'nonce-testNonce123'; style-src 'nonce-testNonce123'; frame-src https://app1.example.com https://app2.example.com",
            csp);
    }
}
