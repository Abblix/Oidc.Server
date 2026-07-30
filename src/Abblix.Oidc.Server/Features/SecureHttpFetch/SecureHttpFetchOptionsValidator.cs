// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
            var member = $"{nameof(SecureHttpFetchOptions)}.{nameof(SecureHttpFetchOptions.AllowedDestinations)}";

            if (!destination.IsAbsoluteUri)
            {
                failures.Add(
                    $"The entry '{destination}' in {member} must be an absolute URI naming a scheme and a host.");

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
