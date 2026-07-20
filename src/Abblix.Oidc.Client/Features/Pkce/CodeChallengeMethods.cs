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

namespace Abblix.Oidc.Client.Features.Pkce;

/// <summary>
/// The code challenge methods of RFC 7636, named as they appear on the wire.
/// </summary>
/// <remarks>
/// Carries the same names as the server side of the family. The two cannot share a declaration, because the
/// base client deliberately does not depend on the server package, and these are wire constants rather than
/// logic.
///
/// Only <see cref="S256"/> is used when building a request. The weaker "plain" transformation is named here
/// because a provider may advertise it, and recognising what a provider offers is not the same as agreeing
/// to use it.
/// </remarks>
public static class CodeChallengeMethods
{
    /// <summary>
    /// The code verifier is sent unhashed, so anyone who reads the authorization request holds it. Recognised
    /// but never used by this client.
    /// </summary>
    public const string Plain = "plain";

    /// <summary>
    /// The code verifier is hashed with SHA-256. What this client sends.
    /// </summary>
    public const string S256 = "S256";

    /// <summary>
    /// The code verifier is hashed with SHA-512.
    /// </summary>
    public const string S512 = "S512";
}
