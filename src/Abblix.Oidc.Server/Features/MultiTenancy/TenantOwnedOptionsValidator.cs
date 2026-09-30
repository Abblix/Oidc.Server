// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;
using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
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
/// <param name="custodianKeys">The custodian's keys named for the whole server, or null when none are.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantOwnedOptionsValidator(
    PairwiseSubjectSettings? pairwiseSubject = null,
    CustodianHeldKeys? custodianKeys = null)
    : IValidateOptions<OidcOptions>
{
    private static readonly OidcOptions Defaults = new();

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = (
            from setting in TenantOwnedSettings.All.Select(setting => setting.Server)
            where IsSet(setting.GetValue(options), setting.GetValue(Defaults))
            select $"{nameof(OidcOptions)}.{setting.Name} applies to the whole server; under multi-tenancy each " +
                   $"tenant declares its own in {nameof(TenantDefinition)}.{setting.Name}, so leave it unset."
        ).ToList();

        if (pairwiseSubject is not null)
        {
            failures.Add(
                $"A {nameof(PairwiseSubjectSettings)} registered for the whole server is not used under " +
                $"multi-tenancy; each tenant declares its own in {nameof(TenantDefinition)}." +
                $"{nameof(TenantDefinition.PairwiseSubject)}, so leave it out.");
        }

        if (custodianKeys is not null)
        {
            failures.Add(
                $"The custodian's keys named for the whole server are not used under multi-tenancy; each tenant " +
                $"names its own in {nameof(TenantDefinition)}.{nameof(TenantDefinition.CustodianKeys)}, so choose " +
                "the custodian placement without naming keys.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Whether a setting holds something other than what a fresh <see cref="OidcOptions"/> holds; a collection
    /// holding nothing declares nothing, whichever instance it is.
    /// </summary>
    private static bool IsSet(object? value, object? defaultValue) => value switch
    {
        null => false,
        IEnumerable collection and not string => collection.Cast<object?>().Any(),
        _ => !Equals(value, defaultValue),
    };
}
