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
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// What a host configures once about its security-event handling: the event dictionary, signing,
/// and - for a profile that weakens the default validation - the reasoned acknowledgement of that
/// weakening. The pipeline itself is composed through the service collection: the default steps
/// register as an ordinary family, and a consumer profile edits them in place through the live
/// composition cursor after <c>AddSecurityEvents</c>.
/// </summary>
public sealed class SecurityEventsOptions
{

    /// <summary>
    /// The event dictionary: which event identifier URIs deserialize into which payload models.
    /// An event dictionary package is a set of calls against this registry.
    /// </summary>
    public EventTypeRegistry Events { get; } = new();

    /// <summary>
    /// Supplies the private key each signing uses - the one thing a transmitter must configure
    /// and a pure receiver never does. Left null, resolving the signer fails loudly naming this
    /// property, instead of a transmitter discovering at first delivery that it signs nothing.
    /// </summary>
    public Func<CancellationToken, Task<JsonWebKey>>? SigningKeySource { get; set; }


}
