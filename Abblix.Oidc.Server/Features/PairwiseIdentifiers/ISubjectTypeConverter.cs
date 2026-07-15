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

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Defines the interface for a service that converts user subject identifiers according to the client's specified
/// subject type. This conversion ensures that the subject identifier presented to the client is in the format
/// that the client expects, based on its configuration.
/// </summary>
/// <remarks>
/// The implementation of this interface should support various subject types, such as "public" or "pairwise",
/// and provide appropriate conversions based on the OpenID Connect specifications.
/// </remarks>
public interface ISubjectTypeConverter
{
    /// <summary>
    /// Lists the subject types that this converter supports. This typically includes "public" and "pairwise"
    /// among others, depending on the OpenID Connect implementation specifics.
    /// </summary>
    IEnumerable<string> SubjectTypesSupported { get; }

    /// <summary>
    /// Converts the real subject identifier into the client-facing one based on the client's subject type: a
    /// pairwise client gets a reversible, per-sector pseudonym; a public client gets the subject unchanged.
    /// </summary>
    /// <param name="subject">The original subject identifier of the end-user.</param>
    /// <param name="clientInfo">Information about the client for which the subject identifier is being transformed.
    /// </param>
    /// <returns>The transformed subject identifier suitable for the client's subject type.</returns>
    string Convert(string subject, ClientInfo clientInfo);

    /// <summary>
    /// Recovers the real subject identifier from the client-facing one produced by <see cref="Convert"/>: a
    /// pairwise client's pseudonym is opened back to the real subject; a public client's subject is returned
    /// unchanged. The <paramref name="clientInfo"/> must be the client the subject was sealed for, as its sector
    /// binds the pseudonym.
    /// </summary>
    /// <param name="subject">The client-facing subject identifier (pairwise pseudonym or real subject).</param>
    /// <param name="clientInfo">The client the subject was issued for.</param>
    /// <returns>The real subject identifier.</returns>
    /// <exception cref="System.InvalidOperationException">Thrown when a pairwise pseudonym cannot be opened:
    /// malformed, sealed for a different sector, or produced under a different pairwise salt.</exception>
    string Recover(string subject, ClientInfo clientInfo);
}
