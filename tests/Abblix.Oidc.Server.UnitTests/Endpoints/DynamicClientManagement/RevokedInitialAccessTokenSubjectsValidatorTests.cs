// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="RevokedInitialAccessTokenSubjectsValidator"/>.
/// </summary>
public class RevokedInitialAccessTokenSubjectsValidatorTests
{
    /// <summary>
    /// Subjects still listed in the server options, which the server no longer reads, stop it from starting, so the
    /// tokens they revoke are not accepted again.
    /// </summary>
    [Fact]
    public void SubjectsLeftInTheServerOptions_AreRefused()
    {
        var validator = new RevokedInitialAccessTokenSubjectsValidator();
#pragma warning disable CS0618
        var leftOver = new OidcOptions { RevokedInitialAccessTokenSubjects = ["partner-app"] };
#pragma warning restore CS0618

        Assert.True(validator.Validate(null, leftOver).Failed);
        Assert.True(validator.Validate(null, new OidcOptions()).Succeeded);
    }
}
