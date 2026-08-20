// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography.X509Certificates;



namespace Abblix.Utils;

/// <summary>
/// Resolves an <see cref="X509Certificate2"/> from a logical <see cref="CertificateId"/>, abstracting away the
/// physical source (file system, certificate store, secret manager, etc.). Implementations are expected to be
/// thread-safe and to surface format or access errors as <see cref="InvalidOperationException"/>.
/// </summary>
public interface ICertificateProvider
{
	/// <summary>
	/// Retrieves an X.509 certificate based on the specified certificate identifier.
	/// </summary>
	/// <param name="certificateId">The identifier of the certificate to retrieve.</param>
	/// <returns>An <see cref="X509Certificate2"/> instance representing the requested certificate.</returns>
	/// <exception cref="KeyNotFoundException">
	/// Thrown if a certificate with the specified identifier is not found.
	/// </exception>
	/// <exception cref="InvalidOperationException">
	/// Thrown if there is an issue in retrieving the certificate, such as issues with certificate format or storage.
	/// </exception>
	X509Certificate2 GetCertificate(CertificateId certificateId);
}
