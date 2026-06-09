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

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
///     Contains IANA-registered Authentication Method Reference (AMR) values as per RFC 8176.
/// </summary>
public static class AuthenticationMethodReferences
{
    /// <summary>Facial recognition biometric (RFC 8176 <c>face</c>).</summary>
    public const string Face = "face";

    /// <summary>Fingerprint biometric (RFC 8176 <c>fpt</c>).</summary>
    public const string Fingerprint = "fpt";

    /// <summary>Geolocation as a factor (RFC 8176 <c>geo</c>).</summary>
    public const string Geolocation = "geo";

    /// <summary>Proof of possession of a hardware-secured key (RFC 8176 <c>hwk</c>).</summary>
    public const string HardwareKey = "hwk";

    /// <summary>Iris scan biometric (RFC 8176 <c>iris</c>).</summary>
    public const string IrisScan = "iris";

    /// <summary>Knowledge-based authentication, e.g. challenge questions (RFC 8176 <c>kba</c>).</summary>
    public const string KnowledgeBased = "kba";

    /// <summary>Multiple-channel authentication where parts of the flow run on different channels (RFC 8176 <c>mca</c>).</summary>
    public const string MultiChannel = "mca";

    /// <summary>Multiple-factor authentication, asserting that two or more independent factors were used (RFC 8176 <c>mfa</c>).</summary>
    public const string MultiFactor = "mfa";

    /// <summary>One-time password (RFC 8176 <c>otp</c>), e.g. TOTP/HOTP code or emailed code.</summary>
    [SuppressMessage("Sonar Code Smell", "S2068:Credentials should not be hard-coded", Justification = "This is a standardized AMR value per RFC 8176, not a credential")]
    public const string OneTimePassword = "otp";

    /// <summary>Personal identification number or unlock pattern (RFC 8176 <c>pin</c>).</summary>
    public const string Pin = "pin";

    /// <summary>Proof of possession of a cryptographic key (RFC 8176 <c>pop</c>).</summary>
    public const string ProofOfPossession = "pop";

    /// <summary>Password-based authentication (RFC 8176 <c>pwd</c>).</summary>
    [SuppressMessage("Sonar Code Smell", "S2068:Credentials should not be hard-coded", Justification = "This is a standardized AMR value per RFC 8176, not a credential")]
    public const string Password = "pwd";

    /// <summary>Risk-based authentication that adapts factors to a computed risk score (RFC 8176 <c>rba</c>).</summary>
    public const string RiskBased = "rba";

    /// <summary>Retina scan biometric (RFC 8176 <c>retina</c>).</summary>
    public const string RetinaScan = "retina";

    /// <summary>Smart-card-based authentication, typically with a client certificate (RFC 8176 <c>sc</c>).</summary>
    public const string SmartCard = "sc";

    /// <summary>SMS-delivered confirmation code (RFC 8176 <c>sms</c>).</summary>
    public const string Sms = "sms";

    /// <summary>Proof of possession of a software-secured key (RFC 8176 <c>swk</c>).</summary>
    public const string SoftwareKey = "swk";

    /// <summary>Telephone call confirmation (RFC 8176 <c>tel</c>).</summary>
    public const string Telephone = "tel";

    /// <summary>User presence test, asserting the user was actively present at authentication (RFC 8176 <c>user</c>).</summary>
    public const string UserPresence = "user";

    /// <summary>Voice biometric (RFC 8176 <c>vbm</c>).</summary>
    public const string VoiceBiometric = "vbm";

    /// <summary>Windows Integrated Authentication via Kerberos or NTLM (RFC 8176 <c>wia</c>).</summary>
    public const string WindowsIntegratedAuth = "wia";

    // Non-standard values (not in IANA registry or RFC 8176):
    // These custom values should be replaced with standard alternatives in production code.

    // "bio" is NOT in IANA registry - RFC 8176 defines specific biometric values instead:
    // Use Face, Fingerprint, IrisScan, RetinaScan, or VoiceBiometric for specific biometric methods.

    // NOT in IANA registry - RFC 8176 has Sms and Telephone for out-of-band methods.
    // The "oob" identifier is used in OAuth for deprecated redirect URIs, not as an AMR value.
    // Use Sms or Telephone for out-of-band authentication, or OneTimePassword for email codes.

    // NOT in IANA registry - RFC 8176 defines SmartCard for certificate-based authentication.
    // Use SmartCard for X.509 certificate authentication, or HardwareKey for hardware-secured keys.
}
