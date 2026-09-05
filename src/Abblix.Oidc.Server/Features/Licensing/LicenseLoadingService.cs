// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// A hosted service that loads the license JWT at application startup.
/// </summary>
/// <remarks>
/// This service is responsible for retrieving the license JWT using the provided <see cref="ILicenseJwtProvider"/>
/// and loading it into the application's licensing system. It ensures that the application operates with the correct
/// licensing configuration from the outset, supporting features and limitations as defined by the license.
///
/// The service runs as part of the application's background services, ensuring the license is loaded before
/// the application starts accepting incoming requests.
/// </remarks>
/// <param name="loggerFactory">Logger factory for initializing the license logger.</param>
/// <param name="licenseJwtProvider">The provider used to retrieve the license JWT.</param>
/// <param name="clock">The clock the loaded licenses are evaluated against once loading has finished.</param>
internal class LicenseLoadingService(
    ILoggerFactory loggerFactory,
    ILicenseJwtProvider licenseJwtProvider,
    TimeProvider clock) : IHostedService
{
    private readonly ILicenseJwtProvider _licenseJwtProvider = Init(loggerFactory, licenseJwtProvider);

    private static ILicenseJwtProvider Init(ILoggerFactory factory, ILicenseJwtProvider provider)
    {
        LicenseLogger.Instance.Init(factory);
        return provider;
    }

    /// <summary>
    /// Starts the service by loading the license JWT.
    /// </summary>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to observe
    /// when the startup process is aborted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation of loading the license JWT.</returns>
    /// <remarks>
    /// If a valid license JWT is retrieved from the <see cref="ILicenseJwtProvider"/>, it is loaded to configure
    /// the application's licensing system. This method is called automatically by the .NET hosting environment
    /// when the application starts.
    /// </remarks>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var licenses = _licenseJwtProvider.GetLicenseJwtAsync();
        if (licenses != null)
        {
            await foreach (var license in licenses.WithCancellation(cancellationToken))
            {
                if (license.HasValue())
                    await LicenseLoader.LoadAsync(license);
            }
        }

        // The loop is where the list stops growing, so this is the first moment anything can be said about
        // the licenses without the answer depending on the order they arrived in. For a deployment holding
        // ONE valid license it is also the only moment: every other route into the reporting is a request
        // path, and the request path returns the cached license without evaluating it while that license
        // is still valid, so nothing would ever say it expires next week.
        //
        // The clock is the host's, while the enforcement in LicenseChecker reads the system clock. They
        // agree wherever TimeProvider.System is registered, which is what the registration extensions do.
        LicenseChecker.ReportLoadedLicenses(clock.GetUtcNow());
    }

    /// <summary>
    /// Stops the service.
    /// </summary>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> used to observe
    /// when the shutdown process is aborted.</param>
    /// <returns>A <see cref="Task"/> that represents the completion of the service's stop operation.</returns>
    /// <remarks>
    /// This method is called automatically by the .NET hosting environment when the application is shutting down.
    /// Since this service does not maintain any resources that need to be explicitly released on stop, the method
    /// completes immediately.
    /// </remarks>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
