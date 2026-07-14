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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Writes the subject claims of a token the server issues for itself, and recovers the real subject when reading
/// one back. For a pairwise client it puts the pairwise pseudonym in <c>sub</c> (so the token matches the
/// id_token) and the real subject in the protected <c>psub</c> claim; for a public client it leaves the real
/// subject in <c>sub</c> and writes no <c>psub</c>. This keeps the pairwise-and-protect logic in one place,
/// shared by the access-token and refresh-token services.
/// </summary>
public interface ISubjectClaimsService
{
    /// <summary>
    /// Writes the subject claims for the given client into the payload: <c>sub</c> becomes the client's subject
    /// type value (pairwise pseudonym or the real subject), and when that differs from the real subject the real
    /// subject is stored, protected, in <c>psub</c>.
    /// </summary>
    /// <param name="payload">The token payload to write into.</param>
    /// <param name="realSubject">The real subject identifier of the end user.</param>
    /// <param name="clientInfo">The client the token is issued for, whose subject type governs the pseudonym.</param>
    void WriteSubject(JsonWebTokenPayload payload, string realSubject, ClientInfo clientInfo);

    /// <summary>
    /// Recovers the real subject from a token payload: the protected <c>psub</c> when present, otherwise
    /// <c>sub</c> (a public client, or a token issued before pairwise protection existed).
    /// </summary>
    /// <param name="payload">The token payload to read from.</param>
    /// <returns>The real subject identifier.</returns>
    string RecoverSubject(JsonWebTokenPayload payload);
}
