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

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common.Implementation;

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
