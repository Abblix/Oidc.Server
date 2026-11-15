// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ReusePrevention;

/// <summary>
/// Detects reuse of an authorization request's transaction-binding values - the PKCE
/// <c>code_challenge</c> (RFC 7636) and the OpenID Connect <c>nonce</c>. Both must be
/// transaction-specific; a client that keeps sending a constant value defeats the protection they provide.
/// RFC 9700 (OAuth 2.0 Security BCP) Section 2.1.1 encourages the authorization server to make a
/// reasonable effort to detect and prevent this. Detection is off unless
/// <see cref="Common.Configuration.OidcOptions.PkceAndNonceReuseDetectionInterval"/> is set.
/// </summary>
public interface IAuthorizationValueReuseDetector
{
    /// <summary>
    /// Reports whether a value of the given kind has already been reserved for this client within the
    /// detection window - that is, whether the client is repeating a value that must be unique per request.
    /// Read while the request is validated, so a repeated value is refused before the end user signs in or
    /// consents; <see cref="TryReserveAsync"/> decides between requests presenting one value together.
    /// </summary>
    /// <param name="tenant">The tenant the client belongs to.</param>
    /// <param name="clientId">The client presenting the value.</param>
    /// <param name="valueKind">A discriminator for the value's role (for example the parameter name), so
    /// a <c>code_challenge</c> and a <c>nonce</c> that happen to coincide are tracked separately.</param>
    /// <param name="value">The raw value; only a hash of it is ever stored.</param>
    /// <returns><c>true</c> when the value was reserved before within the window; otherwise <c>false</c>.
    /// Always <c>false</c> when detection is disabled.</returns>
    Task<bool> IsReusedAsync(TenantDefinition tenant, string clientId, string valueKind, string value);

    /// <summary>
    /// Reserves a value of the given kind for this client for the detection window, answering whether this is its
    /// first use there. Deciding and reserving are one step, so of two requests presenting one value together, one
    /// is told it is the first. Called once per authorization code, before the code is issued, rather than on every
    /// authorization request, so one request processed again across a login or consent redirect is not refused.
    /// </summary>
    /// <param name="tenant">The tenant the client belongs to.</param>
    /// <param name="clientId">The client presenting the value.</param>
    /// <param name="valueKind">A discriminator for the value's role (for example the parameter name), so
    /// a <c>code_challenge</c> and a <c>nonce</c> that happen to coincide are tracked separately.</param>
    /// <param name="value">The raw value; only a hash of it is ever stored.</param>
    /// <returns><c>true</c> when the value is now reserved for the first time within the window, and always when
    /// detection is disabled; <c>false</c> when the client already used it within the window.</returns>
    Task<bool> TryReserveAsync(TenantDefinition tenant, string clientId, string valueKind, string value);
}
