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

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between AuthorizationContext C# record and protobuf message.
/// </summary>
internal static class AuthorizationContextMapper
{
    /// <summary>
    /// Converts a C# AuthorizationContext record to a protobuf message.
    /// </summary>
    public static AuthorizationContext ToProto(this Common.AuthorizationContext source)
    {
        var proto = new AuthorizationContext
        {
            ClientId = source.ClientId,
        };

        proto.Scope.AddRange(source.Scope);

        if (source.RequestedClaims != null)
            proto.RequestedClaims = source.RequestedClaims.ToProto();

        if (source.X509CertificateSha256Thumbprint != null)
            proto.X509CertificateSha256Thumbprint = source.X509CertificateSha256Thumbprint;

        if (source.RedirectUri != null)
            proto.RedirectUri = source.RedirectUri.ToString();

        if (source.Nonce != null)
            proto.Nonce = source.Nonce;

        if (source.CodeChallenge != null)
            proto.CodeChallenge = source.CodeChallenge;

        if (source.CodeChallengeMethod != null)
            proto.CodeChallengeMethod = source.CodeChallengeMethod;

        proto.Resources.AddIfNotNull(source.Resources, r => r.OriginalString);

        return proto;
    }

    /// <summary>
    /// Converts a protobuf AuthorizationContext message to a C# record.
    /// </summary>
    public static Common.AuthorizationContext FromProto(AuthorizationContext source)
    {
        return new Common.AuthorizationContext(
            source.ClientId,
            source.Scope.ToArray(),
            source.RequestedClaims.FromProto())
        {
            X509CertificateSha256Thumbprint = ProtoMapper.GetString(source.X509CertificateSha256Thumbprint, source.HasX509CertificateSha256Thumbprint),
            RedirectUri = ProtoMapper.GetUri(source.RedirectUri, source.HasRedirectUri),
            Nonce = ProtoMapper.GetString(source.Nonce, source.HasNonce),
            CodeChallenge = ProtoMapper.GetString(source.CodeChallenge, source.HasCodeChallenge),
            CodeChallengeMethod = ProtoMapper.GetString(source.CodeChallengeMethod, source.HasCodeChallengeMethod),
            Resources = source.Resources.GetArray(r => new Uri(r)),
        };
    }
}
