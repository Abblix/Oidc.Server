// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Refuses a <see cref="SecureHttpFetchOptions.AllowedDestinations"/> entry that would permit more than it
/// reads as permitting.
/// </summary>
/// <remarks>
/// Matching considers a destination's scheme, host, port and path, and nothing else. An entry carrying a
/// query, a fragment or user information therefore permits every request to that path whatever those parts
/// say, so accepting one would grant a permission wider than the text of the entry - the single failure this
/// option exists to prevent. A relative entry names no host at all and can never match.
/// </remarks>
public class SecureHttpFetchOptionsValidator : IValidateOptions<SecureHttpFetchOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, SecureHttpFetchOptions options)
    {
        if (options.AllowedDestinations is not { Length: > 0 } destinations)
            return ValidateOptionsResult.Success;

        var failures = new List<string>();
        foreach (var destination in destinations)
        {
            const string member = $"{nameof(SecureHttpFetchOptions)}.{nameof(SecureHttpFetchOptions.AllowedDestinations)}";

            if (!destination.IsAbsoluteUri)
            {
                failures.Add($"The entry '{destination}' in {member} must be an absolute URI naming a scheme and a host.");

                // Every question below reads a component only an absolute URI has.
                continue;
            }

            if (destination.Query.Length > 0 || destination.Fragment.Length > 0)
            {
                failures.Add(
                    $"The entry '{destination}' in {member} must carry no query and no fragment: " +
                    "neither takes part in matching, so the entry would permit more than it states.");
            }

            if (destination.UserInfo.Length > 0)
            {
                failures.Add(
                    $"The entry '{destination}' in {member} must carry no user information: " +
                    "it takes no part in matching and is never sent.");
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
