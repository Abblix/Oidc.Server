// Abblix OIDC Server Library
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
