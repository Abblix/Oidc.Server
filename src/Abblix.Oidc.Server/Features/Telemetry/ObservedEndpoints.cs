// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Each endpoint handler the build wraps in a generated decorator, which runs its handling in the endpoint's span and
// records it into the server's metrics. The registration of each endpoint applies its decorator.

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Telemetry;

[assembly: ObservedEndpoint(typeof(IAuthorizationHandler), TelemetryEndpoints.Authorize,
    TagsRequest = true, ObservesResult = true)]
[assembly: ObservedEndpoint(typeof(IPushedAuthorizationHandler), TelemetryEndpoints.PushedAuthorization,
    TagsRequest = true)]
[assembly: ObservedEndpoint(typeof(ITokenHandler), TelemetryEndpoints.Token,
    TagsRequest = true, Dependencies = [typeof(IAuthorizationGrantHandler)])]
[assembly: ObservedEndpoint(typeof(IUserInfoHandler), TelemetryEndpoints.UserInfo)]
[assembly: ObservedEndpoint(typeof(IEndSessionHandler), TelemetryEndpoints.EndSession)]
[assembly: ObservedEndpoint(typeof(IConfigurationHandler), TelemetryEndpoints.Configuration)]
[assembly: ObservedEndpoint(typeof(ICheckSessionHandler), TelemetryEndpoints.CheckSession)]
[assembly: ObservedEndpoint(typeof(IRevocationHandler), TelemetryEndpoints.Revocation)]
[assembly: ObservedEndpoint(typeof(IIntrospectionHandler), TelemetryEndpoints.Introspection)]
[assembly: ObservedEndpoint(typeof(IBackChannelAuthenticationHandler), TelemetryEndpoints.BackChannelAuthentication)]
[assembly: ObservedEndpoint(typeof(IDeviceAuthorizationHandler), TelemetryEndpoints.DeviceAuthorization)]
[assembly: ObservedEndpoint(typeof(IRegisterClientHandler), TelemetryEndpoints.RegisterClient)]
[assembly: ObservedEndpoint(typeof(IReadClientHandler), TelemetryEndpoints.ReadClient)]
[assembly: ObservedEndpoint(typeof(IUpdateClientHandler), TelemetryEndpoints.UpdateClient)]
[assembly: ObservedEndpoint(typeof(IRemoveClientHandler), TelemetryEndpoints.RemoveClient)]
