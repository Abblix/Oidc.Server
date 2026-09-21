// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Thrown when the source of a request has spent its budget of failed client authentications, so its next
/// credential is not looked at. It travels out as HTTP 429 with <c>Retry-After</c> when an interval is known.
/// </summary>
/// <remarks>
/// It is an exception rather than a returned value because what refuses is the client authenticator, whose
/// contract answers a credential with a client or with nothing - and "nothing" already means that the
/// credential was wrong, which this is not. Every endpoint that authenticates a client is covered by that one
/// decision, rather than each of them having to remember to ask.
/// </remarks>
/// <param name="retryAfter">How long before the budget is available again, or null when nothing named it.</param>
public sealed class TooManyAuthenticationFailuresException(TimeSpan? retryAfter)
    : Exception("Too many failed client authentications from this source")
{
    /// <summary>
    /// How long before the budget is available again, as the limiter reports it.
    /// </summary>
    public TimeSpan? RetryAfter { get; } = retryAfter;
}
