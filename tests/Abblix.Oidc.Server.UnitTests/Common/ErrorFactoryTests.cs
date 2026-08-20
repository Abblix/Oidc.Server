// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
