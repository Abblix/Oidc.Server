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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Validation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// Covers the shared request-binding error mapping both transport adapters delegate to: a flat sequence of
/// model-validation messages becomes an <c>invalid_request</c> <see cref="OidcError"/>.
/// </summary>
public class ErrorFactoryTests
{
    [Fact]
    public void InvalidRequest_FromMessages_JoinsAndSetsInvalidRequestCode()
    {
        var error = ErrorFactory.InvalidRequest(["first problem", "second problem"]);

        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("first problem second problem", error.ErrorDescription);
    }

    [Fact]
    public void InvalidRequest_FromBlankOrNoMessages_FallsBackToGenericDescription()
    {
        string[][] blankCases = [[], [""], ["   "], ["", "   "]];

        foreach (var messages in blankCases)
        {
            var error = ErrorFactory.InvalidRequest(messages);

            Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
            Assert.False(string.IsNullOrWhiteSpace(error.ErrorDescription));
        }
    }
}
