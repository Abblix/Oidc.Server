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

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Configuration options for secure HTTP fetching with SSRF protection.
/// </summary>
public class SecureHttpFetchOptions
{
    /// <summary>
    /// Maximum time to wait for the complete HTTP request (including DNS resolution and data transfer).
    /// Default: 30 seconds.
    /// </summary>
    /// <remarks>
    /// This timeout applies to the entire request lifecycle. Lower values provide better protection
    /// against slowloris attacks but may cause failures for legitimate slow responses.
    /// </remarks>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum allowed response size in bytes.
    /// Default: 5 MB (5242880 bytes).
    /// </summary>
    /// <remarks>
    /// This limit prevents denial-of-service attacks via extremely large responses.
    /// Increase this value if you need to fetch larger documents (e.g., large JSON Web Key Sets).
    /// </remarks>
    public long MaxResponseSizeBytes { get; set; } = 5 * 1024 * 1024;
}
