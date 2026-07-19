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

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Encodes authorization endpoint response parameters into a JWT secured for a specific client, as defined by
/// JWT Secured Authorization Response Mode for OAuth 2.0 (JARM),
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html">JARM</see>. This is the framework-agnostic core
/// of JARM: it builds, signs and optionally encrypts the response JWT. The JARM response mode is mapped to its
/// plaintext delivery counterpart separately via <see cref="ResponseModeExtensions.ToDeliveryMode"/>.
/// Hosts (MVC, Minimal API, …) supply the response parameters and emit the resulting <c>response</c> parameter
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
