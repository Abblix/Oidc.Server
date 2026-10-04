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
/// ask it and the registrations would be kept in memory instead, unseen by the host; and one registered for each
/// request or each resolution, which the server's client store, a singleton, would hold for every request after the
/// first.
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
        if (!registered)
            return ValidateOptionsResult.Success;

        if (!MultiTenancyDetection.IsActive(serviceProvider))
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(ITenantClientRegistrationStore)} keeps the registrations of each tenant, so it is served " +
                "only under multi-tenancy: call AddMultiTenancy, or remove the registration of the store.");
        }

        // Two requests share a singleton and nothing else, so the lifetime shows in whether they get one instance
        using var first = serviceProvider.CreateScope();
        using var second = serviceProvider.CreateScope();
        return ReferenceEquals(
            first.ServiceProvider.GetService<ITenantClientRegistrationStore>(),
            second.ServiceProvider.GetService<ITenantClientRegistrationStore>())
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(ITenantClientRegistrationStore)} is registered for each request or each resolution, but " +
                "the server's client store is a singleton and would hold one instance for every request: register " +
                "the store as a singleton.");
#pragma warning restore ABXMT001
    }
}
