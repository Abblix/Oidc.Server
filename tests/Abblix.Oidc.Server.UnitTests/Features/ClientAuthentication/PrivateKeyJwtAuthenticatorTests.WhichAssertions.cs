// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

// Which assertions private_key_jwt reads: those signed with its own algorithms, a JWE, and those signed with no
// method's algorithm; one signed with an HS algorithm is client_secret_jwt's, passed over as presenting nothing
public partial class PrivateKeyJwtAuthenticatorTests
{
    [Theory]
    [InlineData(SigningAlgorithms.RS256, true)]
    [InlineData(SigningAlgorithms.PS256, true)]
    [InlineData(SigningAlgorithms.PS512, true)]
    [InlineData(SigningAlgorithms.None, true)]
    [InlineData(AssertionHeaders.Unreadable, true)]
    [InlineData(AssertionHeaders.Encrypted, true)]
    [InlineData(SigningAlgorithms.HS256, false)]
    [InlineData(SigningAlgorithms.HS512, false)]
    public async Task AnAssertion_IsReadUnlessSignedWithAnHsAlgorithm(string form, bool read)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var assertion = AssertionHeaders.Assertion(form);
        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(
                It.IsAny<TenantDefinition>(), null, It.IsAny<IClientInfoProvider>(), assertion,
                It.IsAny<TokenTypePolicy>(), It.IsAny<IReadOnlySet<string>?>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.None),
            new ClientRequest { ClientAssertionType = ClientAssertionTypes.JwtBearer, ClientAssertion = assertion },
            Clients);

        Assert.Equal(!read, result.GetFailure() is UnauthenticatedCallerError);
        mocks.ClientJwtValidator.Verify(
            v => v.ValidateAsync(
                It.IsAny<TenantDefinition>(), null, It.IsAny<IClientInfoProvider>(), assertion,
                It.IsAny<TokenTypePolicy>(), It.IsAny<IReadOnlySet<string>?>(), It.IsAny<ValidationOptions>()),
            read ? Times.Once() : Times.Never());
    }
}
