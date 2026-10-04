// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Refuses at startup a store of registrations for the tenants on a server without tenants, where nothing would
/// ask it and the registrations would be kept in memory instead, unseen by the host.
/// </summary>
/// <param name="serviceProvider">The container the registrations are resolved from.</param>
internal sealed class TenantClientRegistrationStoreValidator(IServiceProvider serviceProvider)
    : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
#pragma warning disable ABXMT001
        var registered = serviceProvider.GetService<IServiceProviderIsService>() is { } services &&
                         services.IsService(typeof(ITenantClientRegistrationStore));

        return registered && !MultiTenancyDetection.IsActive(serviceProvider)
            ? ValidateOptionsResult.Fail(
                $"{nameof(ITenantClientRegistrationStore)} keeps the registrations of each tenant, so it is served " +
                "only under multi-tenancy: call AddMultiTenancy, or remove the registration of the store.")
            : ValidateOptionsResult.Success;
#pragma warning restore ABXMT001
    }
}
