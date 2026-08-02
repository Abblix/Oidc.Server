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
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// The state one token accumulates on its way through the pipeline: each step reads what earlier
/// steps established and writes what it proved.
/// </summary>
/// <remarks>
/// The context distinguishes the UNVERIFIED reading of the token from the verified one on
/// purpose. <see cref="UnverifiedHeader"/> and <see cref="UnverifiedPayload"/> are what parsing
/// alone yields - enough for the cheap rejections that should not cost a signature check - while
/// <see cref="Token"/> exists only after the signature step, so a later step reaching for the
/// trusted token cannot accidentally read the untrusted one: they are different properties, and
/// the trusted one is null until trust exists.
/// </remarks>
/// <param name="compactToken">The token as received, in compact serialization.</param>
/// <param name="options">What this run expects of the token.</param>
public sealed class SecurityEventTokenValidationContext(
    string compactToken,
    SecurityEventTokenValidationOptions options)
{
    /// <summary>
    /// The token as received. Steps performing cryptography read this, never a re-serialization
    /// of parsed parts: the signature covers these exact bytes.
    /// </summary>
    public string CompactToken { get; } = !string.IsNullOrEmpty(compactToken)
        ? compactToken
        : throw new ArgumentException("A validation run needs a token to run on.", nameof(compactToken));

    /// <summary>
    /// What this run expects of the token.
    /// </summary>
    public SecurityEventTokenValidationOptions Options { get; } = options;

    /// <summary>
    /// The facts established so far.
    /// </summary>
    public SecurityEventTokenValidationState State { get; private set; }

    /// <summary>
    /// The token's header as parsed, before any signature check. Shape, not authorship.
    /// </summary>
    public JsonWebTokenHeader? UnverifiedHeader { get; set; }

    /// <summary>
    /// The token's claims as parsed, before any signature check. Shape, not authorship.
    /// </summary>
    public JsonWebTokenPayload? UnverifiedPayload { get; set; }

    /// <summary>
    /// The validated token: set by the signature step, null until then. From here the claims are
    /// the issuer's words.
    /// </summary>
    public SecurityEventToken? Token { get; set; }

    /// <summary>
    /// The typed event payloads, keyed by event identifier: set by the payload deserialization
    /// step.
    /// </summary>
    public IReadOnlyDictionary<string, IEventPayload>? EventPayloads { get; set; }

    /// <summary>
    /// Records a fact this step has established.
    /// </summary>
    /// <param name="state">The flag to set.</param>
    public void Establish(SecurityEventTokenValidationState state) => State |= state;

    /// <summary>
    /// Declares the facts this step's safety depends on, failing loudly when the pipeline was
    /// composed so that they are not yet established.
    /// </summary>
    /// <remarks>
    /// This is the ordering contract of the pipeline. A composition that, say, deserializes event
    /// payloads before the signature step - parsing attacker-controlled input with the expensive
    /// machinery - dies on its first run with the missing precondition named, instead of running
    /// for months with a check silently skipped.
    /// </remarks>
    /// <param name="required">The facts that must already be established.</param>
    /// <exception cref="InvalidOperationException">A required fact is not established.</exception>
    public void Require(SecurityEventTokenValidationState required)
    {
        var missing = required & ~State;
        if (missing != SecurityEventTokenValidationState.None)
        {
            throw new InvalidOperationException(
                $"The validation pipeline is mis-ordered: this step requires {missing}, which no earlier "
                + "step has established.");
        }
    }
}
