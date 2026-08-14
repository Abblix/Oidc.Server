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

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// The wire names of the CAEP event claims (CAEP 1.0 Sections 2, 3): one registry, because the
/// common claims cross every event type and per-model copies of one name drift apart.
/// </summary>
public static class CaepClaimNames
{
    /// <summary>When the event described by the SET occurred, as unix seconds
    /// (CAEP 1.0 Section 2).</summary>
    public const string EventTimestamp = "event_timestamp";

    /// <summary>The entity that invoked the event (CAEP 1.0 Section 2).</summary>
    public const string InitiatingEntity = "initiating_entity";

    /// <summary>The localizable administrative message for logging and auditing
    /// (CAEP 1.0 Section 2).</summary>
    public const string ReasonAdmin = "reason_admin";

    /// <summary>The localizable message for display to an end user (CAEP 1.0 Section 2).
    /// </summary>
    public const string ReasonUser = "reason_user";

    /// <summary>The changed claims with their new values (CAEP 1.0 Section 3.2.1).</summary>
    public const string Claims = "claims";

    /// <summary>The kind of credential the change concerns (CAEP 1.0 Section 3.3.1).</summary>
    public const string CredentialType = "credential_type";

    /// <summary>What happened to the credential (CAEP 1.0 Section 3.3.1).</summary>
    public const string ChangeType = "change_type";

    /// <summary>The credential's friendly name (CAEP 1.0 Section 3.3.1).</summary>
    public const string FriendlyName = "friendly_name";

    /// <summary>The issuer of the X.509 certificate (CAEP 1.0 Section 3.3.1).</summary>
    public const string X509Issuer = "x509_issuer";

    /// <summary>The serial number of the X.509 certificate (CAEP 1.0 Section 3.3.1).</summary>
    public const string X509Serial = "x509_serial";

    /// <summary>The FIDO2 Authenticator Attestation GUID (CAEP 1.0 Section 3.3.1).</summary>
    public const string Fido2Aaguid = "fido2_aaguid";

    /// <summary>The namespace the assurance level values come from (CAEP 1.0 Section 3.4.1).
    /// </summary>
    public const string Namespace = "namespace";

    /// <summary>The current level - of assurance (CAEP 1.0 Section 3.4.1) or of risk
    /// (Section 3.8.1).</summary>
    public const string CurrentLevel = "current_level";

    /// <summary>The previous level - of assurance (CAEP 1.0 Section 3.4.1) or of risk
    /// (Section 3.8.1).</summary>
    public const string PreviousLevel = "previous_level";

    /// <summary>Whether the assurance level increased or decreased (CAEP 1.0 Section 3.4.1).
    /// </summary>
    public const string ChangeDirection = "change_direction";

    /// <summary>The compliance status before the change (CAEP 1.0 Section 3.5.1).</summary>
    public const string PreviousStatus = "previous_status";

    /// <summary>The compliance status that triggered the event (CAEP 1.0 Section 3.5.1).
    /// </summary>
    public const string CurrentStatus = "current_status";

    /// <summary>The user agent fingerprint computed by the transmitter
    /// (CAEP 1.0 Sections 3.6.1, 3.7.1).</summary>
    public const string FpUa = "fp_ua";

    /// <summary>The session's authentication context class reference
    /// (CAEP 1.0 Section 3.6.1).</summary>
    public const string Acr = "acr";

    /// <summary>The session's authentication methods references (CAEP 1.0 Section 3.6.1).
    /// </summary>
    public const string Amr = "amr";

    /// <summary>The external session identifier correlating this session with a broader one
    /// (CAEP 1.0 Sections 3.6.1, 3.7.1).</summary>
    public const string ExtId = "ext_id";

    /// <summary>The principal entity the observed risk concerns (CAEP 1.0 Section 3.8.1).
    /// </summary>
    public const string Principal = "principal";

    /// <summary>The reason contributing to the risk level change (CAEP 1.0 Section 3.8.1).
    /// </summary>
    public const string RiskReason = "risk_reason";
}
