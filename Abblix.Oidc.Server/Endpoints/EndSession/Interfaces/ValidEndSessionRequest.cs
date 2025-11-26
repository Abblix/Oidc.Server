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

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Represents a valid end-session request with the associated client information.
/// </summary>
public record ValidEndSessionRequest(EndSessionRequest Model, ClientInfo? ClientInfo)
{
    /// <summary>
    /// The end-session request model.
    /// </summary>
    public EndSessionRequest Model { get; init; } = Model;

    /// <summary>
    /// The client information associated with the request.
    /// </summary>
    public ClientInfo? ClientInfo { get; init; } = ClientInfo;
}
