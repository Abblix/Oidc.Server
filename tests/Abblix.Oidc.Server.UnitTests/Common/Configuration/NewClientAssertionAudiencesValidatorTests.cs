// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The assertion audiences the host grants new clients start the host only when the server can apply them: the
/// issuer identifier, alone or widened, a zero read as the issuer alone.
/// </summary>
public class NewClientAssertionAudiencesValidatorTests
{
    [Theory]
    [InlineData(0, true)]
    [InlineData((int)ClientAssertionAudiences.Issuer, true)]
    [InlineData((int)(ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint | ClientAssertionAudiences.AllowArray), true)]
    [InlineData((int)ClientAssertionAudiences.TokenEndpoint, false)]
    [InlineData((int)(ClientAssertionAudiences.Issuer | (ClientAssertionAudiences)8), false)]
    public void TheAssertionAudiencesForNewClients_StartTheHostOnlyWhenTheServerCanApplyThem(int granted, bool starts)
    {
        var options = new OidcOptions
        {
            NewClientOptions = new NewClientOptions { ClientAssertionAudiences = (ClientAssertionAudiences)granted },
        };

        var result = new NewClientAssertionAudiencesValidator().Validate(name: null, options);

        Assert.Equal(starts, result.Succeeded);
    }
}
