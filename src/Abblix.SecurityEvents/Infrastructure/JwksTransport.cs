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

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// The HTTP transport key-set fetches travel on, to the "jwks_uri" of an issuer whose events this host verifies.
/// </summary>
public static class JwksTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(JwksTransport.HttpClientName)</c> reaches the same client the
    /// resolver fetches with, and whatever it chains - a resilience pipeline, a proxy - applies to every fetch.
    /// </summary>
    public const string HttpClientName = "Abblix.SecurityEvents.Jwks";
}
