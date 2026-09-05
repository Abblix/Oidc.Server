// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Represents the identifiers for a certificate, including paths to certificate and key files, and an optional password.
/// </summary>
/// <param name="CertPemFilePath">Path to the certificate file in PEM format.</param>
/// <param name="KeyPemFilePath">Optional path to the key file in PEM format.
/// If not provided, assume the certificate file contains the key.</param>
/// <param name="Password">Optional password for the key file. Required if the key file is encrypted.</param>
public record CertificateId(string CertPemFilePath, string? KeyPemFilePath = null, string? Password = null);
