// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
