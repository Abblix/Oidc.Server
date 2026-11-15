// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Decides which clients have their access tokens bound to the TLS client certificate presented with the token request
/// (RFC 8705 section 3).
/// </summary>
internal static class CertificateBoundAccessTokens
{
    /// <summary>
    /// Whether an access token issued to <paramref name="clientInfo"/> over mutual TLS is bound to the certificate.
    /// </summary>
    /// <remarks>
    /// RFC 8705 section 3.4 has the client convey "the client's intention to use mutual-TLS client certificate-bound
    /// access tokens. If omitted, the default value is false", so authenticating with mutual TLS binds nothing by
    /// itself: section 4 has the two "used independently of each other", and a client sender-constraining its tokens
    /// with DPoP would otherwise need its certificate at every resource as well. A profile issuing certificate-bound
    /// tokens only binds them for every client it holds (FAPI 1.0 Part 2 section 5.2.2: the server "shall only issue
    /// sender-constrained access tokens", with MTLS the mechanism).
    /// </remarks>
    /// <param name="clientInfo">The client the token is issued to.</param>
    /// <param name="requirements">The requirements of the security profile the client is held to.</param>
    public static bool AreIssuedTo(ClientInfo clientInfo, SecurityProfileRequirements requirements)
        => clientInfo.TlsClientCertificateBoundAccessTokens || requirements.RequireCertificateBoundTokens;
}
