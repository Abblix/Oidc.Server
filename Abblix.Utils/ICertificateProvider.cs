// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
