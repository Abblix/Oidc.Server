// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Security;
using Microsoft.Extensions.Http;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// Accepts the conformance suite's self-signed certificate on the server's outgoing calls to the suite: a client's
/// key set, request object, sector identifier and back-channel logout endpoint all live there.
/// </summary>
/// <remarks>
/// The suite's nginx image generates a certificate for <c>localhost</c> at build time, so it fails both the chain
/// and the name check. Only the suite's own host is excused; every other destination is validated as usual, and the
/// address checks of the library's guarded clients stay in place, because the callback is set on the transport
/// underneath them rather than by replacing them.
/// </remarks>
public static class SuiteCertificateTrust
{
    public static IServiceCollection TrustSuiteCertificate(this IServiceCollection services, string suiteHost)
        => services.ConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(builder => Trust(builder.PrimaryHandler, suiteHost)));

    private static void Trust(HttpMessageHandler? handler, string suiteHost)
    {
        switch (handler)
        {
            case DelegatingHandler delegating:
                Trust(delegating.InnerHandler, suiteHost);
                break;

            case HttpClientHandler clientHandler:
                clientHandler.ServerCertificateCustomValidationCallback = (request, _, _, errors)
                    => errors == SslPolicyErrors.None || IsSuite(request.RequestUri, suiteHost);
                break;

            case SocketsHttpHandler socketsHandler:
                socketsHandler.SslOptions.RemoteCertificateValidationCallback = (sender, _, _, errors)
                    => errors == SslPolicyErrors.None ||
                       sender is SslStream stream &&
                       string.Equals(stream.TargetHostName, suiteHost, StringComparison.OrdinalIgnoreCase);
                break;
        }
    }

    private static bool IsSuite(Uri? uri, string suiteHost)
        => uri != null && string.Equals(uri.Host, suiteHost, StringComparison.OrdinalIgnoreCase);
}
