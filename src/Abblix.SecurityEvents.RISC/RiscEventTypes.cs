// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// The event type URIs RISC 1.0 defines (its Section 2), and the one registration call that
/// teaches a receiver's event registry the whole dictionary.
/// </summary>
public static class RiscEventTypes
{
#pragma warning disable S1075 // URIs should not be hardcoded - these are the specification-fixed event type identifiers, not configuration
    /// <summary>
    /// The base URI of the RISC event types (RISC 1.0 Section 2).
    /// </summary>
    private const string BaseUri = "https://schemas.openid.net/secevent/risc/event-type/";
#pragma warning restore S1075

    /// <summary>The account was required to change a credential
    /// (RISC 1.0 Section 2.1).</summary>
    public const string AccountCredentialChangeRequired = BaseUri + "account-credential-change-required";

    /// <summary>The account has been permanently deleted (RISC 1.0 Section 2.2).</summary>
    public const string AccountPurged = BaseUri + "account-purged";

    /// <summary>The account has been disabled (RISC 1.0 Section 2.3).</summary>
    public const string AccountDisabled = BaseUri + "account-disabled";

    /// <summary>The account has been enabled (RISC 1.0 Section 2.4).</summary>
    public const string AccountEnabled = BaseUri + "account-enabled";

    /// <summary>The identifier in the subject has changed (RISC 1.0 Section 2.5).</summary>
    public const string IdentifierChanged = BaseUri + "identifier-changed";

    /// <summary>The identifier in the subject now belongs to a new user
    /// (RISC 1.0 Section 2.6).</summary>
    public const string IdentifierRecycled = BaseUri + "identifier-recycled";

    /// <summary>A credential of the subject was found compromised
    /// (RISC 1.0 Section 2.7).</summary>
    public const string CredentialCompromise = BaseUri + "credential-compromise";

    /// <summary>The account opted into RISC event exchanges (RISC 1.0 Section 2.8.1).</summary>
    public const string OptIn = BaseUri + "opt-in";

    /// <summary>The account initiated an opt-out from RISC event exchanges
    /// (RISC 1.0 Section 2.8.2).</summary>
    public const string OptOutInitiated = BaseUri + "opt-out-initiated";

    /// <summary>The account cancelled a pending opt-out (RISC 1.0 Section 2.8.3).</summary>
    public const string OptOutCancelled = BaseUri + "opt-out-cancelled";

    /// <summary>The opt-out took effect (RISC 1.0 Section 2.8.4).</summary>
    public const string OptOutEffective = BaseUri + "opt-out-effective";

    /// <summary>The account activated a recovery flow (RISC 1.0 Section 2.9).</summary>
    public const string RecoveryActivated = BaseUri + "recovery-activated";

    /// <summary>The account changed some of its recovery information
    /// (RISC 1.0 Section 2.10).</summary>
    public const string RecoveryInformationChanged = BaseUri + "recovery-information-changed";

    /// <summary>All sessions of the account have been revoked (RISC 1.0 Section 2.11).
    /// Deprecated by the specification in favour of the CAEP session-revoked event; kept so a
    /// receiver still understands transmitters that predate the deprecation.</summary>
    public const string SessionsRevoked = BaseUri + "sessions-revoked";

    /// <summary>
    /// Registers every RISC event type with its payload model - the whole dictionary in one
    /// call, so a receiver cannot end up understanding half a profile.
    /// </summary>
    /// <param name="registry">The registry events deserialize through.</param>
    public static EventTypeRegistry RegisterRiscEvents(this EventTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        registry.Register<AccountCredentialChangeRequiredPayload>(AccountCredentialChangeRequired);
        registry.Register<AccountPurgedPayload>(AccountPurged);
        registry.Register<AccountDisabledPayload>(AccountDisabled);
        registry.Register<AccountEnabledPayload>(AccountEnabled);
        registry.Register<IdentifierChangedPayload>(IdentifierChanged);
        registry.Register<IdentifierRecycledPayload>(IdentifierRecycled);
        registry.Register<CredentialCompromisePayload>(CredentialCompromise);
        registry.Register<OptInPayload>(OptIn);
        registry.Register<OptOutInitiatedPayload>(OptOutInitiated);
        registry.Register<OptOutCancelledPayload>(OptOutCancelled);
        registry.Register<OptOutEffectivePayload>(OptOutEffective);
        registry.Register<RecoveryActivatedPayload>(RecoveryActivated);
        registry.Register<RecoveryInformationChangedPayload>(RecoveryInformationChanged);
        registry.Register<SessionsRevokedPayload>(SessionsRevoked);

        return registry;
    }
}
