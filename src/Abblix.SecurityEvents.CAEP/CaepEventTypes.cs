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

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// The event type URIs CAEP 1.0 defines (its Section 3), and the one registration call that
/// teaches a receiver's event registry the whole dictionary.
/// </summary>
public static class CaepEventTypes
{
#pragma warning disable S1075 // URIs should not be hardcoded - these are the specification-fixed event type identifiers, not configuration
    /// <summary>
    /// The base URI of the CAEP event types (CAEP 1.0 Section 3).
    /// </summary>
    private const string BaseUri = "https://schemas.openid.net/secevent/caep/event-type/";
#pragma warning restore S1075

    /// <summary>The session identified by the subject has been revoked
    /// (CAEP 1.0 Section 3.1).</summary>
    public const string SessionRevoked = BaseUri + "session-revoked";

    /// <summary>A claim in the token identified by the subject has changed
    /// (CAEP 1.0 Section 3.2).</summary>
    public const string TokenClaimsChange = BaseUri + "token-claims-change";

    /// <summary>A credential was created, changed, revoked or deleted
    /// (CAEP 1.0 Section 3.3).</summary>
    public const string CredentialChange = BaseUri + "credential-change";

    /// <summary>The authentication assurance level changed since the initial login
    /// (CAEP 1.0 Section 3.4).</summary>
    public const string AssuranceLevelChange = BaseUri + "assurance-level-change";

    /// <summary>A device's compliance status changed (CAEP 1.0 Section 3.5).</summary>
    public const string DeviceComplianceChange = BaseUri + "device-compliance-change";

    /// <summary>The transmitter established a new session for the subject
    /// (CAEP 1.0 Section 3.6).</summary>
    public const string SessionEstablished = BaseUri + "session-established";

    /// <summary>The transmitter observed the subject's session to be present
    /// (CAEP 1.0 Section 3.7).</summary>
    public const string SessionPresented = BaseUri + "session-presented";

    /// <summary>The subject's assessed risk level changed (CAEP 1.0 Section 3.8).</summary>
    public const string RiskLevelChange = BaseUri + "risk-level-change";

    /// <summary>
    /// Registers every CAEP event type with its payload model - the whole dictionary in one
    /// call, so a receiver cannot end up understanding half a profile.
    /// </summary>
    /// <param name="registry">The registry events deserialize through.</param>
    public static EventTypeRegistry RegisterCaepEvents(this EventTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        registry.Register<SessionRevokedPayload>(SessionRevoked);
        registry.Register<TokenClaimsChangePayload>(TokenClaimsChange);
        registry.Register<CredentialChangePayload>(CredentialChange);
        registry.Register<AssuranceLevelChangePayload>(AssuranceLevelChange);
        registry.Register<DeviceComplianceChangePayload>(DeviceComplianceChange);
        registry.Register<SessionEstablishedPayload>(SessionEstablished);
        registry.Register<SessionPresentedPayload>(SessionPresented);
        registry.Register<RiskLevelChangePayload>(RiskLevelChange);

        return registry;
    }
}
