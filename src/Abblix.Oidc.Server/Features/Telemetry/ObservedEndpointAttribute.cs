// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Names an endpoint handler whose decorator the build generates: a sealed partial class named <c>Observed</c> and
/// the interface name without its leading <c>I</c>, which runs each of the handler's methods through
/// <see cref="EndpointObservation.RunAsync{TResult}"/> under <see cref="Endpoint"/>.
/// </summary>
/// <param name="service">The handler interface the decorator implements and wraps.</param>
/// <param name="endpoint">The endpoint the handler serves, one of <see cref="TelemetryEndpoints"/>.</param>
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
internal sealed class ObservedEndpointAttribute(Type service, string endpoint) : Attribute
{
    /// <summary>
    /// The handler interface the decorator implements and wraps.
    /// </summary>
    public Type Service { get; } = service;

    /// <summary>
    /// The endpoint the handler serves, one of <see cref="TelemetryEndpoints"/>.
    /// </summary>
    public string Endpoint { get; } = endpoint;

    /// <summary>
    /// Whether the decorator names an attribute of the request on its span. The generated class then declares
    /// <c>RequestTagOf</c>, taking the method's parameters and returning the attribute's key and value, which a
    /// hand-written part of the class implements.
    /// </summary>
    public bool TagsRequest { get; set; }

    /// <summary>
    /// Whether the decorator looks at what the handler returned. The generated class then declares
    /// <c>Observe</c>, taking the result once the handler has returned it, which a hand-written part of the class
    /// implements.
    /// </summary>
    public bool ObservesResult { get; set; }

    /// <summary>
    /// Services the hand-written part of the decorator needs, each taken in the constructor and kept in a field named
    /// after the type, its leading <c>I</c> dropped and the rest in camel case after an underscore.
    /// </summary>
    public Type[] Dependencies { get; set; } = [];
}
