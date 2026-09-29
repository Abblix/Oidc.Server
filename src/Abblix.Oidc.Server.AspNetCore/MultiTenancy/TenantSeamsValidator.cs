// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Refuses at startup a server in which a service holding tenants' data resolves to one they would share.
/// </summary>
/// <remarks>
/// <see cref="MultiTenancyExtensions.AddMultiTenancy"/> wraps what is registered when it is called; a registration
/// made after it - a host's own storage, a replay cache of another package - replaces the wrapper silently, and
/// every tenant then reads the others' data. Only the finished container can show that.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class TenantSeamsValidator(IServiceProvider serviceProvider) : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions options)
    {
        var shared = TenantSeams.All
            .Select(seam => seam.FindShared(serviceProvider))
            .OfType<string>()
            .Select(service => $"{service} is not kept per tenant: a registration made after " +
                               $"{nameof(MultiTenancyExtensions.AddMultiTenancy)}() replaced it, and its data would " +
                               "be shared between tenants.")
            .ToList();

        return shared.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(shared);
    }
}
