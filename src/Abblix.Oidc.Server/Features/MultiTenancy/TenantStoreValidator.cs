// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup what a store of tenants of the host's own cannot serve: tenants the settings declare, which
/// it does not hold, and keys the server mints, which it keeps only for the tenants the settings declare.
/// </summary>
/// <param name="serviceProvider">The container the store and the key provider are resolved from.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantStoreValidator(IServiceProvider serviceProvider) : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        if (serviceProvider.GetService<ITenantStore>() is OptionsTenantStore or null)
            return ValidateOptionsResult.Success;

        var failures = new List<string>();
        if (options.Tenants.Count > 0)
        {
            failures.Add(
                $"{nameof(MultiTenancyOptions)}.{nameof(MultiTenancyOptions.Tenants)} declares tenants, but the " +
                $"tenants are read from a {nameof(ITenantStore)} of the host's own, so they would never be served. " +
                "Hold them in that store instead.");
        }

        if (serviceProvider.GetService<IAuthServiceKeysProvider>() is MintedKeysProvider)
        {
            failures.Add(
                "The server mints the keys, and keeps a part of its key ring only for each tenant the settings " +
                $"declare, so a tenant read from a {nameof(ITenantStore)} of the host's own would have none to sign " +
                "with. Take each tenant's keys from its settings or from a custodian.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
