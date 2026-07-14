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

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Reversibly protects a subject identifier into an opaque, server-only handle and recovers it. Used to carry
/// the real subject in the <c>psub</c> claim of a token whose <c>sub</c> is a pairwise pseudonym, so the
/// authorization server can recover the real subject while third parties see only the pseudonym.
/// </summary>
/// <remarks>
/// This is the full "protect operation" seam, deliberately shaped like encryption-as-a-service so it accommodates
/// every backend: the built-in implementation performs authenticated encryption locally with a key it holds,
/// while a host can implement it against an HSM, a cloud KMS, or a Vault/OpenBao transit engine where the key
/// never leaves the security boundary. It is asynchronous because those backends are network calls; the built-in
/// local implementation completes synchronously inside the task. Implementations must be authenticated
/// (tamper-evident) so a forged handle is rejected rather than decrypted into an attacker-chosen subject.
/// </remarks>
public interface ISubjectProtector
{
    /// <summary>
    /// Protects a real subject identifier into an opaque, authenticated handle suitable for the <c>psub</c> claim.
    /// </summary>
    /// <param name="subject">The real subject identifier to protect.</param>
    /// <param name="cancellationToken">Cancels a network-backed protect operation.</param>
    /// <returns>An opaque handle that only this server (or its key custodian) can unprotect.</returns>
    Task<string> ProtectAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recovers the real subject identifier from a handle produced by <see cref="ProtectAsync"/>.
    /// </summary>
    /// <param name="handle">The opaque handle previously produced by <see cref="ProtectAsync"/>.</param>
    /// <param name="cancellationToken">Cancels a network-backed unprotect operation.</param>
    /// <returns>The real subject identifier.</returns>
    /// <exception cref="System.Exception">Thrown when the handle is tampered with, malformed, or was produced
    /// under key material this server no longer holds.</exception>
    Task<string> UnprotectAsync(string handle, CancellationToken cancellationToken = default);
}
