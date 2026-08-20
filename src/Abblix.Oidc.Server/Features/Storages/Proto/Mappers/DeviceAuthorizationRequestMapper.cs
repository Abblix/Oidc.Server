// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between DeviceAuthorizationRequest C# record and protobuf message.
/// </summary>
internal static class DeviceAuthorizationRequestMapper
{
    /// <summary>
    /// Converts a C# DeviceAuthorizationRequest record to a protobuf message.
    /// </summary>
    public static DeviceAuthorizationRequest ToProto(this DeviceAuthorization.DeviceAuthorizationRequest source)
    {
        var proto = new DeviceAuthorizationRequest
        {
            ClientId = source.ClientId,
            UserCode = source.UserCode,
            Status = source.Status.ToProtoStatus(),
            ExpiresAt = source.ExpiresAt.ToTimestamp(),
        };

        proto.Scope.AddRange(source.Scope);

        if (source.Resources != null)
        {
            foreach (var resource in source.Resources)
            {
                proto.Resources.Add(resource.ToString());
            }
        }

        if (source.NextPollAt.HasValue)
            proto.NextPollAt = Timestamp.FromDateTimeOffset(source.NextPollAt.Value);

        if (source.AuthorizedGrant != null)
            proto.AuthorizedGrant = source.AuthorizedGrant.ToProto();

        if (source.AuthorizationDetails is { Count: > 0 })
            proto.AuthorizationDetailsJson = source.AuthorizationDetails.ToJsonString();

        return proto;
    }

    /// <summary>
    /// Converts a protobuf DeviceAuthorizationRequest message to a C# record.
    /// </summary>
    public static DeviceAuthorization.DeviceAuthorizationRequest FromProto(this DeviceAuthorizationRequest source)
    {
        Uri[]? resources = null;
        if (source.Resources.Count > 0)
        {
            resources = source.Resources
                .Select(r => new Uri(r))
                .ToArray();
        }

        return new DeviceAuthorization.DeviceAuthorizationRequest(
            source.ClientId,
            source.Scope.ToArray(),
            resources,
            source.UserCode)
        {
            NextPollAt = source.NextPollAt != null ? source.NextPollAt.ToDateTimeOffset() : null,
            ExpiresAt = source.ExpiresAt?.ToDateTimeOffset() ?? default,
            Status = source.Status.FromProtoStatus(),
            AuthorizedGrant = source.AuthorizedGrant?.FromProto(),
            AuthorizationDetails = source.HasAuthorizationDetailsJson
                ? JsonNode.Parse(source.AuthorizationDetailsJson) as JsonArray
                : null,
        };
    }

    private static DeviceAuthorizationStatus ToProtoStatus(this DeviceAuthorization.DeviceAuthorizationStatus source)
    {
        return source switch
        {
            DeviceAuthorization.DeviceAuthorizationStatus.Pending =>
                DeviceAuthorizationStatus.DevicePending,
            DeviceAuthorization.DeviceAuthorizationStatus.Denied =>
                DeviceAuthorizationStatus.DeviceDenied,
            DeviceAuthorization.DeviceAuthorizationStatus.Authorized =>
                DeviceAuthorizationStatus.DeviceAuthorized,
            _ => DeviceAuthorizationStatus.DevicePending,
        };
    }

    private static DeviceAuthorization.DeviceAuthorizationStatus FromProtoStatus(this DeviceAuthorizationStatus source)
    {
        return source switch
        {
            DeviceAuthorizationStatus.DevicePending =>
                DeviceAuthorization.DeviceAuthorizationStatus.Pending,
            DeviceAuthorizationStatus.DeviceDenied =>
                DeviceAuthorization.DeviceAuthorizationStatus.Denied,
            DeviceAuthorizationStatus.DeviceAuthorized =>
                DeviceAuthorization.DeviceAuthorizationStatus.Authorized,
            _ => DeviceAuthorization.DeviceAuthorizationStatus.Pending,
        };
    }
}
