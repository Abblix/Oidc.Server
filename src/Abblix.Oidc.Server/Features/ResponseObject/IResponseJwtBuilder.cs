// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Encodes authorization endpoint response parameters into a JWT secured for a specific client, as defined by
/// JWT Secured Authorization Response Mode for OAuth 2.0 (JARM),
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html">JARM</see>. This is the framework-agnostic core
/// of JARM: it builds, signs and optionally encrypts the response JWT. The JARM response mode is mapped to its
/// plaintext delivery counterpart separately via <see cref="ResponseModeExtensions.ToDeliveryMode"/>.
/// Hosts (MVC, Minimal API, ...) supply the response parameters and emit the resulting <c>response</c> parameter
/// through their own transport layer.
/// </summary>
public interface IResponseJwtBuilder
{
    /// <summary>
    /// Builds the JARM response JWT for the given client. The JWT carries the JARM-mandated <c>iss</c>,
    /// <c>aud</c> and <c>exp</c> claims (JARM §2.1) in addition to the supplied response parameters, is signed
    /// with the client's configured algorithm (default RS256), and is additionally encrypted when the client
    /// registered an encryption algorithm (JARM §2.2).
    /// </summary>
    /// <param name="clientId">The client the response is intended for; supplies the signing/encryption algorithms
    /// and the <c>aud</c> claim.</param>
    /// <param name="parameters">The authorization response parameters (the same set the plaintext response modes
    /// would place on the wire), as name-value pairs.</param>
    /// <returns>A task that returns the encoded response JWT.</returns>
    Task<string> BuildAsync(string? clientId, IReadOnlyList<(string name, string? value)> parameters);
}
