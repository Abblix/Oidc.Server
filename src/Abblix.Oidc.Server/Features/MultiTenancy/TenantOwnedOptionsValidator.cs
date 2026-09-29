// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a multi-tenant deployment that also sets, for the whole server, what each tenant declares
/// for itself.
/// </summary>
/// <remarks>
/// Each tenant declares its own issuer, clients, scopes, resources, user-facing pages and security profile in its
/// <see cref="TenantDefinition"/>, and those are the ones its requests are served with, so the same setting on
/// <see cref="OidcOptions"/> would be ignored while reading as if it applied to every tenant. The same holds for a
/// pairwise key registered for the whole server.
/// </remarks>
/// <param name="pairwiseSubject">The pairwise key registered for the whole server, or null when there is none.
/// </param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantOwnedOptionsValidator(PairwiseSubjectSettings? pairwiseSubject = null)
    : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        // Each setting is named after the tenant's, which OidcOptions spells the same way
        (bool IsSet, string Setting)[] serverWide =
        [
            (options.Issuer is not null, nameof(TenantDefinition.Issuer)),
            (options.Clients?.Any() == true, nameof(TenantDefinition.Clients)),
            (options.Scopes is not null, nameof(TenantDefinition.Scopes)),
            (options.Resources is not null, nameof(TenantDefinition.Resources)),
            (options.DefaultResourceIndicator is not null, nameof(TenantDefinition.DefaultResourceIndicator)),
            (options.AccountSelectionUri is not null, nameof(TenantDefinition.AccountSelectionUri)),
            (options.ConsentUri is not null, nameof(TenantDefinition.ConsentUri)),
            (options.InteractionUri is not null, nameof(TenantDefinition.InteractionUri)),
            (options.LoginUri is not null, nameof(TenantDefinition.LoginUri)),
            (options.RegistrationUri is not null, nameof(TenantDefinition.RegistrationUri)),
            (
                options.DefaultSecurityProfile != ClientSecurityProfile.None,
                nameof(TenantDefinition.DefaultSecurityProfile)),
        ];

        var failures = (
            from setting in serverWide
            where setting.IsSet
            select $"{nameof(OidcOptions)}.{setting.Setting} applies to the whole server; under multi-tenancy each " +
                   $"tenant declares its own in {nameof(TenantDefinition)}.{setting.Setting}, so leave it unset."
        ).ToList();

        if (pairwiseSubject is not null)
        {
            failures.Add(
                $"A {nameof(PairwiseSubjectSettings)} registered for the whole server is not used under " +
                $"multi-tenancy; each tenant declares its own in {nameof(TenantDefinition)}." +
                $"{nameof(TenantDefinition.PairwiseSubject)}, so leave it out.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
