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
public class ClientCertificateBinder : IModelBinder
{
    /// <summary>
    /// Resolves the client certificate for the current connection and assigns it as the binding result.
    /// The result is null when no certificate is present, which is the expected case for non-mTLS clients.
    /// </summary>
    public async Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var connection = bindingContext.HttpContext.Connection;

        var clientCert = connection.ClientCertificate
                         ?? await connection.GetClientCertificateAsync();

        bindingContext.Result = ModelBindingResult.Success(clientCert);
    }
}
