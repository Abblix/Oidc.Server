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
/// Refuses at startup two configured clients under one id, the case of its letters aside.
/// </summary>
/// <remarks>
/// The client registry looks ids up regardless of case, so it cannot hold both and fails when it is first built -
/// on a request, with an error that names neither client.
/// </remarks>
public sealed class ClientIdsOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = (options.Clients ?? [])
            .GroupBy(client => client.ClientId, StringComparer.OrdinalIgnoreCase)
            .Where(same => same.Count() > 1)
            .Select(same =>
                $"{same.Count()} clients are configured under the id " +
                $"{string.Join(" and ", same.Select(client => $"'{client.ClientId}'").Distinct())}; client ids " +
                "are compared regardless of case, so give each client an id of its own.")
            .ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
