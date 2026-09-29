// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a configured resource the resource registry cannot hold: one named by a relative address,
/// or two under one address.
/// </summary>
/// <remarks>
/// The registry refuses both when it is first built, which is on a request, and every request that looks a
/// resource up then fails without naming the resource.
/// </remarks>
public sealed class ResourceDefinitionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var resources = options.Resources ?? [];

        // RFC 8707 Section 2: a resource indicator is an absolute URI, so a relative one could never be requested
        var failures = (
            from resource in resources
            where !resource.Resource.IsAbsoluteUri
            select $"The resource '{resource.Resource}' must be named by an absolute URI (RFC 8707 Section 2)."
        ).Concat(
            from resource in resources
            where resource.Resource.IsAbsoluteUri
            group resource by resource.Resource into same
            where same.Count() > 1
            select $"{same.Count()} resources are defined under '{same.Key}'; define each resource once."
        ).ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
