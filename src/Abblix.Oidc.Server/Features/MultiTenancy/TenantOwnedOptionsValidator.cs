// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a multi-tenant deployment that also sets, for the whole server, what each tenant declares
/// for itself.
/// </summary>
/// <remarks>
/// Each tenant declares its own issuer and clients in its <see cref="TenantDefinition"/>, and those are the ones
/// its requests are served with, so the same setting on <see cref="OidcOptions"/> would be ignored while reading
/// as if it applied to every tenant.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantOwnedOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new List<string>();

        if (options.Issuer is not null)
            failures.Add(Refusal(nameof(OidcOptions.Issuer), nameof(TenantDefinition.Issuer)));

        if (options.Clients?.Any() == true)
            failures.Add(Refusal(nameof(OidcOptions.Clients), nameof(TenantDefinition.Clients)));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static string Refusal(string setting, string tenantSetting)
        => $"{nameof(OidcOptions)}.{setting} applies to the whole server; under multi-tenancy each tenant declares " +
           $"its own in {nameof(TenantDefinition)}.{tenantSetting}, so leave it unset.";
}
