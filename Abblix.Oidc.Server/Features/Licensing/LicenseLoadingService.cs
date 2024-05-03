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
internal class LicenseLoadingService
    : IHostedService
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LicenseLoadingService"/> with the specified license JWT provider.
    /// </summary>
    /// <param name="loggerFactory"></param>
    /// <param name="licenseJwtProvider">The provider used to retrieve the license JWT.</param>
    public LicenseLoadingService(
        ILoggerFactory loggerFactory,
        ILicenseJwtProvider licenseJwtProvider)
    {
        LicenseLogger.Instance.Init(loggerFactory);
        _licenseJwtProvider = licenseJwtProvider;
    }

    private readonly ILicenseJwtProvider _licenseJwtProvider;

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
            await foreach (var license in licenses)
            {
                if (license.HasValue())
                    await LicenseLoader.LoadAsync(license);
            }
        }
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
