// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Issuer;

/// <summary>
/// The issuer taken from the request is the application's address as written: an Issuer Identifier is a
/// case-sensitive URL (OpenID Connect Core 1.0 section 1.2), compared as written, so nothing normalizes it.
/// </summary>
public class RequestBasedIssuerProviderTests
{
    [Theory]
    [InlineData("https://Auth.Example.COM")]
    [InlineData("https://auth.example.com:443/tenant")]
    public void TheIssuer_IsTheApplicationAddressAsWritten(string address)
    {
        var requestInfo = new Mock<IRequestInfoProvider>();
        requestInfo.Setup(r => r.ApplicationUri).Returns(new Uri(address));

        Assert.Equal(address, new RequestBasedIssuerProvider(requestInfo.Object).GetIssuer());
    }
}
