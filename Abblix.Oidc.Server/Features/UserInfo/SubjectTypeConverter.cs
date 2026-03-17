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
using System.Web;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Implements conversion of subject identifiers for end-users based on the subject type requested by the client.
/// Uses HMAC-SHA256 with a server-side secret salt for pairwise identifiers, per OpenID Connect Core Section 8.1.
/// </summary>
public class SubjectTypeConverter(PairwiseSubjectSettings? settings = null) : ISubjectTypeConverter
{
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
    /// For pairwise: HMAC(salt, UrlEncode(sector) + "&amp;" + UrlEncode(subject)) → base64url.
    /// The HMAC algorithm is configurable via PairwiseSubjectSettings.HashAlgorithm (default: SHA256).
    /// For public: returns the original subject identifier unchanged.
    /// </summary>
    public string Convert(string subject, ClientInfo clientInfo)
    {
        return clientInfo.SubjectType switch
        {
            SubjectTypes.Pairwise => ComputePairwiseSubject(subject, clientInfo),
            _ => subject,
        };
    }

    private string ComputePairwiseSubject(string subject, ClientInfo clientInfo)
    {
        if (settings == null)
        {
            throw new InvalidOperationException(
                $"PairwiseSubjectSettings must be configured to use pairwise subject identifiers " +
                $"(client '{clientInfo.ClientId}' has {nameof(clientInfo.SubjectType)}={clientInfo.SubjectType})");
        }

        var sector = clientInfo.SectorIdentifier ?? clientInfo.ClientId;
        var data = Encoding.UTF8.GetBytes($"{HttpUtility.UrlEncode(sector)}&{HttpUtility.UrlEncode(subject)}");
        var algorithm = settings.HashAlgorithm;
        var salt = System.Convert.FromBase64String(settings.Salt);

        var hash = algorithm.Name switch
        {
            nameof(HashAlgorithmName.SHA256) => HMACSHA256.HashData(salt, data),
            nameof(HashAlgorithmName.SHA384) => HMACSHA384.HashData(salt, data),
            nameof(HashAlgorithmName.SHA512) => HMACSHA512.HashData(salt, data),
            nameof(HashAlgorithmName.SHA1) => HMACSHA1.HashData(salt, data),
            _ => throw new NotSupportedException($"HMAC algorithm '{algorithm.Name}' is not supported"),
        };

        return HttpServerUtility.UrlTokenEncode(hash);
    }
}
