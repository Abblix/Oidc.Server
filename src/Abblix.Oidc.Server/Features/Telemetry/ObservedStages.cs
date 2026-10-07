// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Each service the build wraps in a generated decorator that runs its work as a stage of the request, in a span under
// the endpoint's span. The registration of each endpoint applies its decorators.

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Telemetry;

[assembly: ObservedStage(typeof(IAuthorizationRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IAuthorizationRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IPushedAuthorizationRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IPushedAuthorizationRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(ITokenRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(ITokenRequestProcessor), TelemetryStages.Issuance)]
[assembly: ObservedStage(typeof(IUserInfoRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IUserInfoRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IEndSessionRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IEndSessionRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IRevocationRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IRevocationRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IIntrospectionRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IIntrospectionRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IBackChannelAuthenticationRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IBackChannelAuthenticationRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IDeviceAuthorizationRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IDeviceAuthorizationRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IRegisterClientRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IRegisterClientRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IClientRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IReadClientRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IUpdateClientRequestValidator), TelemetryStages.Validation)]
[assembly: ObservedStage(typeof(IUpdateClientRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IRemoveClientRequestProcessor), TelemetryStages.Processing)]
[assembly: ObservedStage(typeof(IClientAuthenticator), TelemetryStages.ClientAuthentication, RefusesWithNull = true)]
[assembly: ObservedStage(typeof(IAuthorizationGrantHandler), TelemetryStages.Grant)]
