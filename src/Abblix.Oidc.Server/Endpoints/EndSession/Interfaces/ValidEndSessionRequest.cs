// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

    /// <summary>
    /// Whether the end user has to be asked whether to log out before this request is acted upon (OpenID Connect
    /// RP-Initiated Logout 1.0 section 2), because the request carried no answer of theirs and no hint naming the
    /// session it would end.
    /// </summary>
    public bool ConfirmationRequired { get; init; }
}
