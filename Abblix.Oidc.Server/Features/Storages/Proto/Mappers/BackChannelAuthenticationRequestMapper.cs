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
        };

        if (source.NextPollAt.HasValue)
            proto.NextPollAt = Timestamp.FromDateTimeOffset(source.NextPollAt.Value);

        return proto;
    }

    /// <summary>
    /// Converts a protobuf BackChannelAuthenticationRequest message to a C# record.
    /// </summary>
    public static BackChannelAuthentication.BackChannelAuthenticationRequest FromProto(this BackChannelAuthenticationRequest source)
    {
        return new BackChannelAuthentication.BackChannelAuthenticationRequest(
            source.AuthorizedGrant.FromProto())
        {
            NextPollAt = source.NextPollAt != null ? source.NextPollAt.ToDateTimeOffset() : null,
            Status = source.Status.FromProtoStatus(),
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
