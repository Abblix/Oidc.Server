// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


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

        // OIDC Core 5.5 permits a requested claim to carry a null value (e.g. {"email": null}) - a voluntary
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
