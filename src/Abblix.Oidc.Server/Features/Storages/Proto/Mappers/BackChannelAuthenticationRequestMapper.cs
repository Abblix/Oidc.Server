// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between BackChannelAuthenticationRequest C# record and protobuf message.
/// </summary>
internal static class BackChannelAuthenticationRequestMapper
{
    /// <summary>
    /// Converts a C# BackChannelAuthenticationRequest record to a protobuf message.
    /// </summary>
    public static BackChannelAuthenticationRequest ToProto(this BackChannelAuthentication.BackChannelAuthenticationRequest source)
    {
        var proto = new BackChannelAuthenticationRequest
        {
            AuthorizedGrant = source.AuthorizedGrant.ToProto(),
            Status = ToProtoStatus(source.Status),
            ExpiresAt = source.ExpiresAt.ToTimestamp(),
        };

        if (source.NextPollAt.HasValue)
            proto.NextPollAt = source.NextPollAt.Value.ToTimestamp();

        // Ping/push delivery fields - absent for poll mode, kept null-distinct via the
        // proto3 optional accessors so the round-trip never coerces null into "".
        if (source.ClientNotificationEndpoint is not null)
            proto.ClientNotificationEndpoint = source.ClientNotificationEndpoint.ToString();

        if (source.ClientNotificationToken is not null)
            proto.ClientNotificationToken = source.ClientNotificationToken;

        if (source.RequestedSubjects is { } accepted)
        {
            proto.RequestedSubjects = new AcceptedSubjects();
            proto.RequestedSubjects.Values.AddRange(accepted);
        }

        return proto;
    }

    /// <summary>
    /// Converts a protobuf BackChannelAuthenticationRequest message to a C# record.
    /// </summary>
    public static BackChannelAuthentication.BackChannelAuthenticationRequest FromProto(this BackChannelAuthenticationRequest source)
    {
        return new BackChannelAuthentication.BackChannelAuthenticationRequest(
            source.AuthorizedGrant.FromProto(),
            source.ExpiresAt.ToDateTimeOffset())
        {
            NextPollAt = source.NextPollAt?.ToDateTimeOffset(),
            Status = source.Status.FromProtoStatus(),
            ClientNotificationEndpoint = source.HasClientNotificationEndpoint
                ? new Uri(source.ClientNotificationEndpoint)
                : null,
            RequestedSubjects = source.RequestedSubjects?.Values.ToArray(),
            ClientNotificationToken = source.HasClientNotificationToken
                ? source.ClientNotificationToken
                : null,
        };
    }

    private static BackChannelAuthenticationStatus ToProtoStatus(
        BackChannelAuthentication.BackChannelAuthenticationStatus source)
    {
        return source switch
        {
            BackChannelAuthentication.BackChannelAuthenticationStatus.Pending =>
                BackChannelAuthenticationStatus.Pending,
            BackChannelAuthentication.BackChannelAuthenticationStatus.Denied =>
                BackChannelAuthenticationStatus.Denied,
            BackChannelAuthentication.BackChannelAuthenticationStatus.Authenticated =>
                BackChannelAuthenticationStatus.Authenticated,
            _ => BackChannelAuthenticationStatus.Pending,
        };
    }

    private static BackChannelAuthentication.BackChannelAuthenticationStatus FromProtoStatus(this BackChannelAuthenticationStatus source)
    {
        return source switch
        {
            BackChannelAuthenticationStatus.Pending =>
                BackChannelAuthentication.BackChannelAuthenticationStatus.Pending,
            BackChannelAuthenticationStatus.Denied =>
                BackChannelAuthentication.BackChannelAuthenticationStatus.Denied,
            BackChannelAuthenticationStatus.Authenticated =>
                BackChannelAuthentication.BackChannelAuthenticationStatus.Authenticated,
            _ => BackChannelAuthentication.BackChannelAuthenticationStatus.Pending,
        };
    }
}
