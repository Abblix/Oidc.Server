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
/// Fails at startup on a negative key rollover propagation window.
/// </summary>
/// <remarks>
/// The window is how long the key set may be cached, sent as its <c>max-age</c>, and how long a new key waits before
/// it signs. A negative window would send a <c>max-age</c> no cache can read and would mean the same as none, so it
/// is a mistake rather than a choice. No window at all is accepted: it is a deployment whose clients do not cache
/// the key set, and a new key then signs at once.
/// </remarks>
public sealed class KeyRolloverPropagationValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.KeyRolloverPropagation < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.KeyRolloverPropagation)} is {options.KeyRolloverPropagation}, but it is how long " +
                "the published key set may be cached and how long a new key waits before it signs, so it cannot be " +
                "negative. Set it to the longest a client caches the key set, or to zero when no client caches it.");
        }

        return ValidateOptionsResult.Success;
    }
}
