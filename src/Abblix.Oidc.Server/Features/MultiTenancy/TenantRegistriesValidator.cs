// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a registry of clients, scopes, resources or pairwise keys that the host brought itself.
/// </summary>
/// <remarks>
/// The server's own registries keep one set for each tenant, built from what the tenant declares. One the host
/// brings keeps one set for every tenant, since nothing tells it which tenant a request is for: a client registered
/// at one tenant would authenticate at every other. Until the contract for a registry that answers per tenant
/// exists, only the server's own are served under multi-tenancy.
/// </remarks>
/// <param name="serviceProvider">The container the registries are resolved from.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantRegistriesValidator(IServiceProvider serviceProvider) : IValidateOptions<MultiTenancyOptions>
{
    private static readonly (Type Service, Type PerTenant)[] Registries =
    [
        (typeof(IClientInfoProvider), typeof(ClientInfoStorage)),
        (typeof(IClientInfoManager), typeof(ClientInfoStorage)),
        (typeof(IScopeManager), typeof(ScopeManager)),
        (typeof(IResourceManager), typeof(ResourceManager)),
        (typeof(ISubjectTypeConverter), typeof(IssuerSubjectTypeConverter)),
    ];

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var failures = (
            from registry in Registries
            let found = Find(registry.Service)
            where found.Registered is not null && found.Registered.GetType() != registry.PerTenant ||
                  found.Failure is not null
            let whose = found.Registered is { } registered
                ? $"({registered.GetType().FullName})"
                : $"(it could not be resolved at startup: {found.Failure})"
            select $"{registry.Service.Name} is the host's own {whose}, which keeps one set for every tenant, so " +
                   "each tenant would see the others'; a wrapper around the server's own counts as the host's too. " +
                   "Under multi-tenancy leave it to the server, which keeps one for each tenant from what the " +
                   "tenant declares."
        ).ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// The registered service, or why it could not be resolved here: the server's own resolve from the root, so a
    /// failure is a registration of the host's - one scoped to a request, for one.
    /// </summary>
    private (object? Registered, string? Failure) Find(Type service)
    {
        try
        {
            return (serviceProvider.GetService(service), null);
        }
        catch (InvalidOperationException exception)
        {
            return (null, exception.Message);
        }
    }
}
