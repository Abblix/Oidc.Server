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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Contains IANA-registered Authentication Method Reference (AMR) values as per RFC 8176.
/// </summary>
public static class AuthenticationMethodReferences
{
    public const string Face = "face";                  // Facial recognition
    public const string Fingerprint = "fpt";            // Fingerprint biometric
    public const string Geolocation = "geo";            // Geolocation
    public const string HardwareKey = "hwk";            // Hardware-secured key
    public const string IrisScan = "iris";              // Iris scan biometric
    public const string KnowledgeBased = "kba";         // Knowledge-based authentication
    public const string MultiChannel = "mca";           // Multiple-channel authentication
    public const string MultiFactor = "mfa";            // Multiple-factor authentication
    public const string OneTimePassword = "otp";        // One-time password
    public const string Pin = "pin";                    // PIN or pattern
    public const string ProofOfPossession = "pop";      // Proof-of-possession of a key
    public const string Password = "pwd";               // Password-based authentication
    public const string RiskBased = "rba";              // Risk-based authentication
    public const string RetinaScan = "retina";          // Retina scan biometric
    public const string SmartCard = "sc";               // Smart card
    public const string Sms = "sms";                    // SMS confirmation
    public const string SoftwareKey = "swk";            // Software-secured key
    public const string Telephone = "tel";              // Telephone call confirmation
    public const string UserPresence = "user";          // User presence test
    public const string VoiceBiometric = "vbm";         // Voice biometric
    public const string WindowsIntegratedAuth = "wia";  // Windows Integrated Authentication
}
