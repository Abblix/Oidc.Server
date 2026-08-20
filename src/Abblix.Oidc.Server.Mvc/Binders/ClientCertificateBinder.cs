// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Model binder that supplies the negotiated TLS client X.509 certificate to an action parameter,
/// enabling support for mutual-TLS client authentication and certificate-bound access tokens (RFC 8705).
/// Reads from <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.ClientCertificate"/>, falling back
/// to <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.GetClientCertificateAsync"/> for renegotiation.
/// When the server is fronted by a reverse proxy that terminates TLS, register
/// <c>CertificateForwardingMiddleware</c> beforehand so the forwarded header is hydrated into the connection.
/// </summary>
[Binds(typeof(ClientCertificateAttribute))]
public class ClientCertificateBinder : IModelBinder
{
    /// <summary>
    /// Resolves the client certificate for the current connection and assigns it as the binding result.
    /// The result is null when no certificate is present, which is the expected case for non-mTLS clients.
    /// </summary>
    public async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var connection = bindingContext.HttpContext.Connection;
        var clientCert = connection.ClientCertificate ?? await connection.GetClientCertificateAsync();
        bindingContext.Result = ModelBindingResult.Success(clientCert);
    }
}
