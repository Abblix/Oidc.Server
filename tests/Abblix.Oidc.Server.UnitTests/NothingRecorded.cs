// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Moq;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// The token status check of a server that has recorded nothing about any token: no rotation, no revocation and no
/// cutoff, as for a test whose subject is not revocation.
/// </summary>
internal static class NothingRecorded
{
    /// <summary>
    /// A check that refuses no token.
    /// </summary>
    public static TokenStatusCheck StatusCheck
    {
        get
        {
            var registry = new Mock<ITokenRegistry>();
            registry
                .Setup(r => r.GetStatusAsync(It.IsAny<TenantDefinition>(), It.IsAny<string>()))
                .ReturnsAsync(JsonWebTokenStatus.Unknown);

            var cutoffs = new Mock<IRevocationCutoffChecker>();
            cutoffs
                .Setup(c => c.CheckAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebTokenPayload>()))
                .ReturnsAsync((JwtValidationError?)null);

            return new TokenStatusCheck(
                registry.Object,
                cutoffs.Object,
                new GrantRevocation(registry.Object, Mock.Of<IClientInfoProvider>()));
        }
    }
}
