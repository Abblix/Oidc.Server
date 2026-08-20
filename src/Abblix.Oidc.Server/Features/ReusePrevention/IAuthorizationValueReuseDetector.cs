// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Reports whether a value of the given kind has already been recorded for this client within the
    /// detection window - that is, whether the client is repeating a value that must be unique per request.
    /// </summary>
    /// <param name="clientId">The client presenting the value.</param>
    /// <param name="valueKind">A discriminator for the value's role (for example the parameter name), so
    /// a <c>code_challenge</c> and a <c>nonce</c> that happen to coincide are tracked separately.</param>
    /// <param name="value">The raw value; only a hash of it is ever stored.</param>
    /// <returns><c>true</c> when the value was seen before within the window; otherwise <c>false</c>.
    /// Always <c>false</c> when detection is disabled.</returns>
    Task<bool> IsReusedAsync(string clientId, string valueKind, string value);

    /// <summary>
    /// Records a value as used by this client so a later reuse within the detection window is caught.
    /// A no-op when detection is disabled. Called once per issued authorization code, not on every
    /// authorization request, so re-processing one request across a login or consent redirect is not flagged.
    /// </summary>
    Task RecordAsync(string clientId, string valueKind, string value);
}
