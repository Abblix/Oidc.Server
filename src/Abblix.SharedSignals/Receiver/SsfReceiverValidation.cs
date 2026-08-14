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

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Names the receiver's validation profile: the keyed
/// <c>ISecurityEventTokenValidator</c> family this package creates, edits and resolves, so its
/// demands on a SET never collide with what another consumer of security event tokens in the same
/// host demands of its own kind.
/// </summary>
public static class SsfReceiverValidation
{
    /// <summary>
    /// The profile's service key: the SET's own <c>typ</c> value. The key is the wire
    /// discriminator of the token kind because that is precisely what profiles part over - each
    /// pins its <c>typ</c> and shapes the claims that kind demands - so "which profile" and
    /// "which token kind" are one question with one spelling. Public because a host that adds
    /// its OWN steps to the receiver's validation - a deployment-specific issuer pin, say -
    /// reaches the profile's cursor by this key. A second consumer of the SAME token kind does
    /// not share it: a profile has one owner, and that consumer names a key of its own.
    /// </summary>
    public const string ProfileKey = JsonWebTokenTypes.SecurityEvent;
}
