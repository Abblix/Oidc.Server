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

using System;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SecureHttpFetchOptionsValidator"/>, which refuses a named destination that
/// would permit more than its text says.
/// </summary>
public class SecureHttpFetchOptionsValidatorTests
{
    private static SecureHttpFetchOptionsValidator Validator => new();

    private static bool Succeeds(params Uri[] destinations)
        => Validator.Validate(null, new SecureHttpFetchOptions { AllowedDestinations = destinations }).Succeeded;

    [Theory]
    [InlineData("http://localhost:5002")]
    [InlineData("http://localhost:5002/manage/api/signout-backchannel-oidc")]
    [InlineData("https://backend-staging:5001/connect/token")]
    public void Validate_DestinationOfSchemeHostPortAndPath_Succeeds(string destination)
    {
        Assert.True(Succeeds(new Uri(destination)));
    }

    // Matching reads scheme, host, port and path and nothing else, so any component beyond those would sit
    // in the entry unread - the entry would permit every query at that path while appearing to permit one.
    [Theory]
    [InlineData("http://localhost:5002/api?tenant=abblix")]
    [InlineData("http://localhost:5002/api#section")]
    [InlineData("http://user:secret@localhost:5002/api")]
    public void Validate_DestinationCarryingAnUnreadComponent_Fails(string destination)
    {
        Assert.False(Succeeds(new Uri(destination)));
    }

    // A relative entry names no host, so it can never match anything and is a configuration mistake rather
    // than a permission.
    [Fact]
    public void Validate_RelativeDestination_Fails()
    {
        Assert.False(Succeeds(new Uri("/manage/api/signout-backchannel-oidc", UriKind.Relative)));
    }

    // One bad entry is refused even in the company of good ones - otherwise the mistake would be reported
    // only when it happened to sit first.
    [Fact]
    public void Validate_OneBadDestinationAmongGoodOnes_Fails()
    {
        Assert.False(Succeeds(
            new Uri("http://localhost:5002/api"),
            new Uri("http://localhost:5003/api?tenant=abblix"),
            new Uri("https://backend-staging:5001/connect/token")));
    }

    [Fact]
    public void Validate_WithNoDestinations_Succeeds()
    {
        Assert.True(Validator.Validate(null, new SecureHttpFetchOptions()).Succeeded);
        Assert.True(Succeeds());
    }
}
