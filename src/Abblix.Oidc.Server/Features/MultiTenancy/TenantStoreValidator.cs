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
/// Refuses at startup keys the server mints beside a store of tenants of the host's own: the server keeps a part of
/// its key ring only for each tenant the settings declare, so a tenant the store holds beyond them would have no key
/// to sign with.
/// </summary>
/// <param name="serviceProvider">The container the store and the key provider are resolved from.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantStoreValidator(IServiceProvider serviceProvider) : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        return serviceProvider.GetService<ITenantStore>() is not OptionsTenantStore &&
               serviceProvider.GetService<IAuthServiceKeysProvider>() is MintedKeysProvider
            ? ValidateOptionsResult.Fail(
                "The server mints the keys, and keeps a part of its key ring only for each tenant the settings " +
                $"declare, so a tenant read from an {nameof(ITenantStore)} of the host's own would have none to sign " +
                "with. Take each tenant's keys from its settings or from a custodian.")
            : ValidateOptionsResult.Success;
    }
}
