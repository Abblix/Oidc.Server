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

namespace Abblix.Utils;

/// <summary>
/// Represents the identifiers for a certificate, including paths to certificate and key files, and an optional password.
/// </summary>
/// <param name="CertPemFilePath">Path to the certificate file in PEM format.</param>
/// <param name="KeyPemFilePath">Optional path to the key file in PEM format.
/// If not provided, assume the certificate file contains the key.</param>
/// <param name="Password">Optional password for the key file. Required if the key file is encrypted.</param>
public record CertificateId(string CertPemFilePath, string? KeyPemFilePath = null, string? Password = null);
