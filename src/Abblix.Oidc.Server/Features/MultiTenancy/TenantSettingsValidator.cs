// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a tenant whose own settings the server's checks would refuse, naming the tenant.
/// </summary>
/// <remarks>
/// Under multi-tenancy the settings a tenant declares are left unset on <see cref="OidcOptions"/>, so the checks
/// judging them there judge nothing, and a tenant's mistake - a default resource it does not define, a client its
/// security profile cannot admit - would surface on the first request that meets it. So every check of
/// <see cref="OidcOptions"/> judges, for each tenant, the settings that tenant's requests are served with: the
/// server's own, with each setting the tenant declares under the same name taken from the tenant. A check added
/// later is applied to tenants with nothing more to do.
/// </remarks>
/// <param name="options">The server's own settings.</param>
/// <param name="validators">The checks of the server's settings.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantSettingsValidator(
    IOptions<OidcOptions> options,
    IEnumerable<IValidateOptions<OidcOptions>> validators) : IValidateOptions<MultiTenancyOptions>
{
    private static readonly (PropertyInfo Tenant, PropertyInfo Server)[] TenantOwned = (
        from tenantProperty in typeof(TenantDefinition).GetProperties(BindingFlags.Public | BindingFlags.Instance)
        let serverProperty = typeof(OidcOptions).GetProperty(tenantProperty.Name)
        where serverProperty is { CanWrite: true } &&
              serverProperty.PropertyType.IsAssignableFrom(tenantProperty.PropertyType)
        select (tenantProperty, serverProperty)
    ).ToArray();

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions tenants)
    {
        var failures = (
            from tenant in tenants.Tenants
            let servedWith = ServedWith(tenant)
            from validator in validators

            // It refuses exactly the settings a tenant's view carries
            where validator is not TenantOwnedOptionsValidator
            let result = validator.Validate(Options.DefaultName, servedWith)
            where result.Failed
            from failure in result.Failures ?? []
            select $"Tenant '{tenant.Id}': {failure}"
        ).ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private OidcOptions ServedWith(TenantDefinition tenant)
    {
        var servedWith = options.Value with { };
        foreach (var (tenantProperty, serverProperty) in TenantOwned)
            serverProperty.SetValue(servedWith, tenantProperty.GetValue(tenant));

        return servedWith;
    }
}
