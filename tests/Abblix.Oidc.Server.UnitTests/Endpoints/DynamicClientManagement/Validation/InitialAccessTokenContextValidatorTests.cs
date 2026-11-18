// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// The registration pipeline's step asks the one judge of the initial access token a host asks too, and only for a
/// registration: an update is authorized by the registration access token.
/// </summary>
public class InitialAccessTokenContextValidatorTests
{
    private static readonly IReadOnlyList<string> Lines = [$"{TokenTypes.Bearer} the-token"];

    [Fact]
    public async Task ARegistration_IsJudgedByTheValidator()
    {
        var refusal = new OidcError(ErrorCodes.InvalidToken, "refused");
        var validator = new Mock<IInitialAccessTokenValidator>(MockBehavior.Strict);
        validator.Setup(v => v.ValidateAsync(It.IsAny<TenantDefinition>(), Lines)).ReturnsAsync(refusal);

        var result = await new InitialAccessTokenContextValidator(validator.Object).ValidateAsync(
            SingleIssuer.Tenant,
            new ClientRegistrationValidationContext(new ClientRegistrationRequest { AuthorizationHeaderLines = Lines }));

        Assert.Same(refusal, result);
    }

    [Fact]
    public async Task AnUpdate_IsNotJudged()
    {
        var validator = new Mock<IInitialAccessTokenValidator>(MockBehavior.Strict);

        var result = await new InitialAccessTokenContextValidator(validator.Object).ValidateAsync(
            SingleIssuer.Tenant,
            new ClientRegistrationValidationContext(new ClientRegistrationRequest { AuthorizationHeaderLines = Lines })
            {
                Operation = DynamicClientOperation.Update,
            });

        Assert.Null(result);
    }
}
