// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// A device authorization request asking for offline_access is refused only for a client whose offline access is
/// disabled: the end user approves the request on the device, so a client that may receive offline access with
/// prompt=consent receives it here too.
/// </summary>
public class ScopeValidatorTests
{
    private delegate bool TryGetCallback(TenantDefinition tenant, string scope, out ScopeDefinition? definition);

    [Theory]
    [InlineData(OfflineAccess.Disabled, ErrorCodes.InvalidScope)]
    [InlineData(OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, null)]
    public async Task ValidateAsync_OfflineAccess_IsRefusedOnlyWhenDisabled(OfflineAccess offlineAccess, string? error)
    {
        var scopeManager = new Mock<IScopeManager>();
        scopeManager
            .Setup(m => m.TryGet(TestTenant.Matched, It.IsAny<string>(), out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(scope);
                return true;
            }));
        var validator = new ScopeValidator(scopeManager.Object);
        var context = new DeviceAuthorizationValidationContext(
            new DeviceAuthorizationRequest { Scope = [Scopes.OpenId, Scopes.OfflineAccess] },
            new ClientRequest { ClientId = "device-client" })
        {
            ClientInfo = new ClientInfo("device-client") { OfflineAccess = offlineAccess },
        };

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// A device authorization request naming no scope is served with the client's default scope, and a client
    /// required to name its scope is refused one naming none with <c>invalid_scope</c> (RFC 6749 section 3.3).
    /// </summary>
    [Theory]
    [InlineData(false, null)]
    [InlineData(true, ErrorCodes.InvalidScope)]
    public async Task ARequestNamingNoScope_IsServedWithTheDefaultOrRefused(bool requireScope, string? error)
    {
        var scopeManager = new Mock<IScopeManager>();
        scopeManager
            .Setup(m => m.TryGet(TestTenant.Matched, It.IsAny<string>(), out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(scope);
                return true;
            }));
        var validator = new ScopeValidator(scopeManager.Object);
        var context = new DeviceAuthorizationValidationContext(
            new DeviceAuthorizationRequest(), new ClientRequest { ClientId = "device-client" })
        {
            ClientInfo = new ClientInfo("device-client") { DefaultScope = [Scopes.Profile], RequireScope = requireScope },
        };

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(error, result?.Error);
        Assert.Equal(requireScope ? null : Scopes.Profile, context.Scope is [var served] ? served.Scope : null);
    }
}
