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
/// Maps between RequestedClaims C# record and protobuf message.
/// </summary>
internal static class RequestedClaimsMapper
{
    /// <summary>
    /// Converts a C# RequestedClaims record to a protobuf message.
    /// </summary>
    public static RequestedClaims ToProto(this Model.RequestedClaims source)
    {
        var proto = new RequestedClaims();

        if (source.UserInfo != null)
        {
            foreach (var (key, value) in source.UserInfo)
            {
                proto.UserInfo.Add(new ClaimEntry
                {
                    Key = key,
                    Value = value.ToProtoDetails(),
                });
            }
        }

        if (source.IdToken != null)
        {
            foreach (var (key, value) in source.IdToken)
            {
                proto.IdToken.Add(new ClaimEntry
                {
                    Key = key,
                    Value = value.ToProtoDetails(),
                });
            }
        }

        return proto;
    }

    /// <summary>
    /// Converts a protobuf RequestedClaims message to a C# record.
    /// </summary>
    public static Model.RequestedClaims? FromProto(this RequestedClaims? source)
    {
        if (source == null)
            return null;

        Dictionary<string, Model.RequestedClaimDetails>? userInfo = null;
        if (source.UserInfo.Count > 0)
        {
            userInfo = new Dictionary<string, Model.RequestedClaimDetails>();
            foreach (var entry in source.UserInfo)
            {
                userInfo[entry.Key] = entry.Value.FromProtoDetails();
            }
        }

        Dictionary<string, Model.RequestedClaimDetails>? idToken = null;
        if (source.IdToken.Count > 0)
        {
            idToken = new Dictionary<string, Model.RequestedClaimDetails>();
            foreach (var entry in source.IdToken)
            {
                idToken[entry.Key] = entry.Value.FromProtoDetails();
            }
        }

        return new Model.RequestedClaims
        {
            UserInfo = userInfo,
            IdToken = idToken,
        };
    }

    private static RequestedClaimDetails ToProtoDetails(this Model.RequestedClaimDetails? source)
    {
        var proto = new RequestedClaimDetails();

        // OIDC Core 5.5 permits a requested claim to carry a null value (e.g. {"email": null}) — a voluntary
        // claim with no constraints. Persist it as an empty detail rather than dereferencing the null source.
        if (source is null)
            return proto;

        if (source.Essential.HasValue)
            proto.Essential = source.Essential.Value;

        if (source.Value != null)
            proto.Value = source.Value.ToValue();

        if (source.Values != null)
            proto.Values = source.Values.ToListValue();

        return proto;
    }

    private static Model.RequestedClaimDetails FromProtoDetails(this RequestedClaimDetails source)
    {
        return new Model.RequestedClaimDetails
        {
            Essential = source.HasEssential ? source.Essential : null,
            Value = source.Value.ToObject(),
            Values = source.Values.ToObjectArray(),
        };
    }
}
