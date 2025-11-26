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

using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the notification payload sent to the client in ping mode.
/// </summary>
public sealed record BackChannelPingNotificationRequest : IBackChannelNotificationRequest
{
    /// <summary>
    /// The authentication request identifier that is ready for token retrieval.
    /// </summary>
    [JsonPropertyName(Parameters.AuthReqId)]
    public required string AuthenticationRequestId { get; init; }

    public static class Parameters
    {
        public const string AuthReqId = "auth_req_id";
    }
}
