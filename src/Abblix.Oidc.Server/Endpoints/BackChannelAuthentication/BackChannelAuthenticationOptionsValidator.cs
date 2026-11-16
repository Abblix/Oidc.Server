// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;

/// <summary>
/// Fails at startup on backchannel authentication lifetimes no request can be served with, instead of a server error
/// on every backchannel authentication request.
/// </summary>
/// <remarks>
/// A pending request is stored for its lifetime plus <see cref="BackChannelAuthenticationOptions.MaximumExpiry"/>, so
/// a poll after its expiry is still answered expired_token. That sum has to be a duration the clock and the store can
/// hold, which a maximum of <see cref="TimeSpan.MaxValue"/> - a natural way to write "no limit" - is not, and a
/// maximum of no length leaves no time past expiry at all. A default above the maximum would hand a client that names
/// no lifetime more than one naming the longest it may ask for.
/// </remarks>
internal sealed class BackChannelAuthenticationOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// The longest <see cref="BackChannelAuthenticationOptions.MaximumExpiry"/> accepted. A request waits for a person
    /// to answer on a device, and one still waiting after a year is waited on by nobody; at twice this, the longest a
    /// pending request is stored, the expiry stays far inside what every clock and store holds.
    /// </summary>
    internal static readonly TimeSpan LongestMaximumExpiry = TimeSpan.FromDays(365);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var settings = options.BackChannelAuthentication;

        if (settings.MaximumExpiry <= TimeSpan.Zero || LongestMaximumExpiry < settings.MaximumExpiry)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.BackChannelAuthentication)}.{nameof(settings.MaximumExpiry)} is " +
                $"{settings.MaximumExpiry}. A pending backchannel authentication request is kept for its lifetime " +
                "plus this value, so it must be positive and no longer than " +
                $"{LongestMaximumExpiry}. Set the longest lifetime a client may request.");
        }

        if (settings.DefaultExpiry <= TimeSpan.Zero || settings.MaximumExpiry < settings.DefaultExpiry)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.BackChannelAuthentication)}.{nameof(settings.DefaultExpiry)} is " +
                $"{settings.DefaultExpiry}, which is not a lifetime between zero and " +
                $"{nameof(settings.MaximumExpiry)} ({settings.MaximumExpiry}): a request naming no lifetime " +
                "would expire when made, or outlive the longest one a client may ask for.");
        }

        return ValidateOptionsResult.Success;
    }
}
