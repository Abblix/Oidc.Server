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
            Status = source.Status.FromProtoStatus(),
            AuthorizedGrant = source.AuthorizedGrant?.FromProto(),
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
