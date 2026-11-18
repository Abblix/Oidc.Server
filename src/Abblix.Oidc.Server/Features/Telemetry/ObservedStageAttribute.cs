// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Names a service whose decorator the build generates to run each of its methods as a stage of the request, through
/// <see cref="StageObservation.RunAsync{TResult}"/> under <see cref="Stage"/>. The decorator is a sealed partial
/// class named <c>Observed</c> and the interface name without its leading <c>I</c>.
/// </summary>
/// <param name="service">The interface the decorator implements and wraps.</param>
/// <param name="stage">The stage the service performs, one of <see cref="TelemetryStages"/>.</param>
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
internal sealed class ObservedStageAttribute(Type service, string stage) : Attribute
{
    /// <summary>
    /// The interface the decorator implements and wraps.
    /// </summary>
    public Type Service { get; } = service;

    /// <summary>
    /// The stage the service performs, one of <see cref="TelemetryStages"/>.
    /// </summary>
    public string Stage { get; } = stage;

    /// <summary>
    /// Whether the service answers a refusal with null, as a client authenticator does for a credential that does not
    /// verify, so the decorator closes the span with an error when the result is null.
    /// </summary>
    public bool RefusesWithNull { get; set; }

    /// <summary>
    /// Whether the service never refuses, as a provider of what the end user consented to does. A stage returning
    /// neither a Result nor an authorization response is refused by the build unless it says so. It speaks only for
    /// such a result and only without <see cref="RefusesWithNull"/>, which takes precedence: the two describe
    /// different services and are not set together. A stage returning a nullable Result is refused either way, since
    /// the nullable hides the Result's refusal.
    /// </summary>
    public bool NeverRefuses { get; set; }
}
