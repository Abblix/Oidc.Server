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

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Implements conversion of subject identifiers for end-users based on the subject type requested by the client.
/// </summary>
/// <remarks>
/// Subject identifiers can be either directly provided to the client (public) or transformed into a pairwise
/// identifier to ensure user privacy across different clients. This implementation supports both "public" and
/// "pairwise" subject types as defined by the OpenID Connect specification.
/// </remarks>
public class SubjectTypeConverter : ISubjectTypeConverter
{
    /// <summary>
    /// The subject types supported by this converter.
    /// </summary>
    public IEnumerable<string> SubjectTypesSupported
    {
        get
        {
            yield return SubjectTypes.Public;
            yield return SubjectTypes.Pairwise;
        }
    }

    /// <summary>
    /// Converts the subject identifier based on the client's subject type.
    /// For "pairwise" subject type clients, it generates a unique and stable subject identifier by hashing
    /// the original subject identifier with the client's sector identifier or client ID.
    /// For "public" subject type clients, it returns the original subject identifier.
    /// </summary>
    /// <param name="subject">The original subject identifier of the end-user.</param>
    /// <param name="clientInfo">Information about the client for which the subject identifier is being transformed,
    /// including the subject type and sector identifier if applicable.</param>
    /// <returns>The transformed subject identifier for the end-user based on the client's subject type.</returns>
    /// <remarks>
    /// This method ensures that end-users are represented differently to different clients
    /// (when using "pairwise" subject type) to enhance user privacy, or consistently represented to all clients
    /// (when using "public" subject type) based on the client's configuration.
    /// </remarks>
    public string Convert(string subject, ClientInfo clientInfo)
    {
        switch (clientInfo.SubjectType)
        {
            case SubjectTypes.Pairwise:
                var subjectBytes = Encoding.UTF8.GetBytes(subject + (clientInfo.SectorIdentifier ?? clientInfo.ClientId));
                var hashData = SHA512.HashData(subjectBytes);
                return HttpServerUtility.UrlTokenEncode(hashData);

            default:
                return subject;
        }
    }
}
