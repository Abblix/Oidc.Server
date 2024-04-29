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

using System.Security.Cryptography.X509Certificates;



namespace Abblix.Utils;

/// <summary>
/// Defines an interface for providing X.509 certificates.
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
