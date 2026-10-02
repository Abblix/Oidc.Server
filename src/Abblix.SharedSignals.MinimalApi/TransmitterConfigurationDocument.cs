// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using System.Text.Json.Nodes;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Composes the transmitter configuration document (SSF 1.0 Section 7.1).
/// </summary>
internal static class TransmitterConfigurationDocument
{
    /// <summary>
    /// The configuration document (SSF 1.0 Section 7.1), composed from the deployment's options and
    /// what is actually served: every address comes from a locator that knows whether anything
    /// answers there, so a deployment mapping the document alone advertises no management API and no
    /// poll delivery rather than addresses that answer 404.
    /// </summary>
    internal static TransmitterConfiguration ConfigurationDocumentOf(
        SharedSignalsTransmitterOptions options,
        PollEndpointLocator pollEndpoints,
        ManagementEndpointLocator managementEndpoints)
    {
        var deliveryMethods = new List<string> { PushDeliveryMethod.MethodUri };
        if (pollEndpoints.IsOffered)
        {
            deliveryMethods.Add(PollDeliveryMethod.MethodUri);
        }

        return new TransmitterConfiguration
        {
            SpecVersion = TransmitterConfiguration.SpecVersions.Final,
            Issuer = options.Issuer,
            JwksUri = options.JwksUri,
            DeliveryMethodsSupported = deliveryMethods,
            ConfigurationEndpoint = managementEndpoints.Of(ManagementRoutes.Stream),
            StatusEndpoint = managementEndpoints.Of(ManagementRoutes.Status),
            AddSubjectEndpoint = managementEndpoints.Of(ManagementRoutes.AddSubject),
            RemoveSubjectEndpoint = managementEndpoints.Of(ManagementRoutes.RemoveSubject),
            VerificationEndpoint = managementEndpoints.Of(ManagementRoutes.Verify),
            AuthorizationSchemes = options.AuthorizationSchemes switch
            {
                null => [OAuthAuthorizationScheme()],

                // The host said "advertise none" explicitly. Publishing an empty array would advertise a
                // member with no schemes in it, which says less than omitting it.
                { Count: 0 } => null,

                var supplied => supplied,
            },
            DefaultSubjects = options.DefaultSubjectsValue,
        };
    }

    /// <summary>
    /// The one scheme description the CAEP Interoperability Profile names.
    /// </summary>
    private static JsonObject OAuthAuthorizationScheme() => new()
    {
        [TransmitterConfiguration.ParameterNames.SpecUrn] =
            TransmitterConfiguration.AuthorizationSchemeUrns.OAuth2,
    };
}
