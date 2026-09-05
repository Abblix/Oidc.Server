// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Credential Change (CAEP 1.0 Section 3.3): a credential was created, changed, revoked or
/// deleted - a password reset, a certificate enrollment or revocation, a second-factor or
/// passwordless credential enrolled or removed. When
/// <see cref="CaepEventPayload.EventTimestamp"/> is included it is the moment of the change.
/// </summary>
public sealed record CredentialChangePayload : CaepEventPayload
{
    /// <summary>
    /// The credential kinds Section 3.3.1 names. The set is open by the specification's own
    /// words: any other credential type mutually supported by the transmitter and the receiver
    /// is equally legal, which is why <see cref="CredentialType"/> is a string rather than a
    /// closed enumeration.
    /// </summary>
    public static class CredentialTypes
    {
        /// <summary>A password.</summary>
        public const string Password = "password";

        /// <summary>A PIN.</summary>
        public const string Pin = "pin";

        /// <summary>An X.509 certificate.</summary>
        public const string X509 = "x509";

        /// <summary>A FIDO2 platform authenticator.</summary>
        public const string Fido2Platform = "fido2-platform";

        /// <summary>A FIDO2 roaming authenticator.</summary>
        public const string Fido2Roaming = "fido2-roaming";

        /// <summary>A FIDO U2F authenticator.</summary>
        public const string FidoU2f = "fido-u2f";

        /// <summary>A verifiable credential.</summary>
        public const string VerifiableCredential = "verifiable-credential";

        /// <summary>A voice-call phone factor.</summary>
        public const string PhoneVoice = "phone-voice";

        /// <summary>An SMS phone factor.</summary>
        public const string PhoneSms = "phone-sms";

        /// <summary>An app-based factor.</summary>
        public const string App = "app";
    }

    /// <summary>
    /// The values the "change_type" member may carry (CAEP 1.0 Section 3.3.1) - this set is
    /// closed, unlike the credential types.
    /// </summary>
    public static class ChangeTypes
    {
        /// <summary>The credential was created.</summary>
        public const string Create = "create";

        /// <summary>The credential was revoked.</summary>
        public const string Revoke = "revoke";

        /// <summary>The credential was updated.</summary>
        public const string Update = "update";

        /// <summary>The credential was deleted.</summary>
        public const string Delete = "delete";
    }

    /// <summary>
    /// REQUIRED. The kind of credential, one of <see cref="CredentialTypes"/> or any other
    /// type the two parties mutually support (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.CredentialType)]
    public required string CredentialType { get; init; }

    /// <summary>
    /// REQUIRED. What happened to the credential, one of <see cref="ChangeTypes"/>
    /// (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ChangeType)]
    public required string ChangeType { get; init; }

    /// <summary>
    /// OPTIONAL. The credential's friendly name (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.FriendlyName)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FriendlyName { get; init; }

    /// <summary>
    /// OPTIONAL. The issuer of the X.509 certificate (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.X509Issuer)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? X509Issuer { get; init; }

    /// <summary>
    /// OPTIONAL. The serial number of the X.509 certificate (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.X509Serial)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? X509Serial { get; init; }

    /// <summary>
    /// OPTIONAL. The FIDO2 Authenticator Attestation GUID (CAEP 1.0 Section 3.3.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Fido2Aaguid)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Fido2Aaguid { get; init; }
}
