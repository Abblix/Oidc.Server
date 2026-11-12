#Requires -Version 7.3
<#
.SYNOPSIS
Runs OpenID Foundation conformance test plans against the conformance test host, locally and without a person.

.DESCRIPTION
Starts the suite from its published images, publishes the test host and runs it as a container on the suite's
network, runs the suite's own plan runner, then removes what it started. The exit code is the runner's: zero when
every module passed or waits only for a reviewer to look at a screenshot, non-zero on any unexpected failure.

Without -SuitePath the run takes the suite's newest numbered release: its scripts from the git tag and its images
under the same tag. A release that is tagged but whose images are not published yet stops the run, naming it, rather
than falling back to an older release.

.PARAMETER SuitePath
A checkout of https://gitlab.com/openid/conformance-suite to take the runner script and compose file from, instead
of the newest release. The images are then the ones the IMAGE_TAG environment variable names, or latest.

.PARAMETER Plan
Test plans to run, each with its variants and optionally a module list after a colon, in the runner's syntax.
Several are passed from a PowerShell prompt or with the call operator; under pwsh -File a list arrives as one
string, so there one plan goes here and several go in a file named by -PlanFile.

.PARAMETER PlanFile
A file with one plan per line, lines starting with # ignored. Used when -Plan is not given; by default the plans
Abblix OIDC Server is certified against, certified-plans.txt.

.PARAMETER ResultsPath
A directory to leave the evidence of the run in: the runner's exported results, the screenshots the browser driver
took, and the logs of the host and the driver.

.PARAMETER KeepRunning
Leaves the suite and the host running afterwards, so a failed module can be opened in the suite's web interface.

.EXAMPLE
./conformance/run.ps1

.EXAMPLE
./conformance/run.ps1 -SuitePath ../conformance-suite -Plan 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]:oidcc-server'
#>
[CmdletBinding()]
param(
    [string] $SuitePath,

    [string[]] $Plan,

    [string] $PlanFile = (Join-Path $PSScriptRoot 'certified-plans.txt'),

    [string] $ResultsPath,

    [switch] $KeepRunning
)

$ErrorActionPreference = 'Stop'

# The names the configuration file and the suite agree on: the host is reached as oidc-host, and the suite
# publishes its own base URL, which resolves to the suite's nginx both inside its network and on this machine.
$ProjectName = 'abblix-oidf'
$Network = "${ProjectName}_default"
$HostContainer = 'oidc-host'
$SuiteUrl = 'https://localhost.emobix.co.uk:8443/'
$SuiteMtlsUrl = 'https://localhost.emobix.co.uk:8444/'
$DiscoveryUrl = 'https://oidc-host:9443/.well-known/openid-configuration'
$RotateUrl = 'https://oidc-host:9443/conformance/rotate-keys'
$KeyRotationModule = 'oidcc-server-rotate-keys'

# Where the suite's releases come from: the git tags carry the scripts, the registry the images built from them
$SuiteRepository = 'https://gitlab.com/openid/conformance-suite.git'
$SuiteProjectApi = 'https://gitlab.com/api/v4/projects/openid%2Fconformance-suite'
$SuiteImages = @('openid/conformance-suite', 'openid/conformance-suite/nginx')

$RuntimeImage = 'mcr.microsoft.com/dotnet/aspnet:11.0'
$ProbeImage = 'curlimages/curl:8.10.1'
$RunnerImage = 'python:3.12-slim'

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$HostProject = Join-Path $RepositoryRoot 'tests/Abblix.Oidc.Server.MinimalApi.Conformance.TestHost'
$HostAssembly = 'Abblix.Oidc.Server.MinimalApi.Conformance.TestHost.dll'
$PublishDirectory = Join-Path ([IO.Path]::GetTempPath()) 'abblix-conformance-host'
$BrowserContainer = 'oidf-browser'
$BrowserImage = 'abblix-oidf-browser'
$BrowserScreenshots = '/tmp/screenshots'

# The runner's own dependencies, pinned with their hashes in place of the suite's unpinned requirements.txt
$RunnerInstall = 'pip install -q --root-user-action=ignore --only-binary :all: --require-hashes -r /config/requirements-runner.txt'

function Write-Step([string] $Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-LastExit([string] $What) {
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE"
    }
}

function Wait-Until {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Condition,
        [Parameter(Mandatory)] [string] $What,
        [int] $TimeoutSeconds = 180
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (& $Condition) {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "$What did not become ready within $TimeoutSeconds seconds"
}

function Test-SuiteReady {
    try {
        $response = Invoke-WebRequest -Uri "${SuiteUrl}api/runner/available" -SkipCertificateCheck `
            -TimeoutSec 5 -SkipHttpErrorCheck
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Test-HostReady {
    # The host is reachable only on the suite's network, so the probe runs there too
    $status = docker run --rm --network $Network $ProbeImage -sk -o /dev/null -w '%{http_code}' $DiscoveryUrl 2>$null
    return ($status -join '') -eq '200'
}

function Select-SuiteReleases {
    # The numbered releases among the tags, newest first, compared as versions so that release-v5.3.10 comes before
    # release-v5.3.4; a tag of any other shape is not a release and is left out
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Tags
    )
    @($Tags | ForEach-Object {
            if ($_ -match '^release-v(\d+)\.(\d+)\.(\d+)$') {
                [pscustomobject]@{ Tag = $_; Version = [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) }
            }
        } | Sort-Object -Property Version -Descending | ForEach-Object { $_.Tag })
}

function Get-SuiteReleaseTags {
    [CmdletBinding()]
    param()
    $lines = @(git ls-remote --tags --refs $SuiteRepository 'release-v*')
    Assert-LastExit 'git ls-remote (conformance suite tags)'
    @($lines | ForEach-Object { ($_ -split "`t", 2)[1] } | Where-Object { $_ } | ForEach-Object { $_ -replace '^refs/tags/', '' })
}

function Test-SuiteImagesPublished {
    # Whether every image the compose file starts is published under the tag; an answer other than found or not
    # found is a failure of the question, never a no
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Tag,
        [Parameter(Mandatory)] [object[]] $Repositories
    )
    foreach ($repository in $Repositories) {
        $response = Invoke-WebRequest -Uri "$SuiteProjectApi/registry/repositories/$($repository.id)/tags/$Tag" `
            -SkipHttpErrorCheck -TimeoutSec 30
        if ($response.StatusCode -eq 404) {
            return $false
        }
        if ($response.StatusCode -ne 200) {
            throw "The suite's registry answered $($response.StatusCode) about $($repository.path):$Tag"
        }
    }
    return $true
}

function Resolve-SuiteRelease {
    # The newest numbered release of the suite. A newer release that is tagged but not yet built stops the run instead
    # of being passed over, because then the run would test against a release the suite has already replaced
    [CmdletBinding()]
    param()
    $repositories = @(Invoke-RestMethod -Uri "$SuiteProjectApi/registry/repositories?per_page=100" -TimeoutSec 30 |
        ForEach-Object { $_ } | Where-Object { $_.path -in $SuiteImages })
    if ($repositories.Count -ne $SuiteImages.Count) {
        throw "The suite's registry does not list all of $($SuiteImages -join ', ')"
    }
    $newest = @(Select-SuiteReleases -Tags @(Get-SuiteReleaseTags)) | Select-Object -First 1
    if (-not $newest) {
        throw "The suite has no tag shaped like release-vX.Y.Z at $SuiteRepository"
    }
    if (-not (Test-SuiteImagesPublished -Tag $newest -Repositories $repositories)) {
        throw "The suite's newest release $newest is tagged, but its images are not published yet; run again once they are"
    }
    return $newest
}

function Split-KeyRotation {
    # The plan specification the runner gets, without the key rotation module, and whether the plan had that module.
    # The runner starts the module the moment it is configured, before anyone can rotate the server's keys, so it
    # runs in a step of its own; a specification already naming its modules keeps the others it names
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Specification,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $AvailablePlans
    )
    $parts = $Specification -split ':', 2
    $name = ($parts[0] -split '\[', 2)[0].Trim()
    $modules = if ($parts.Count -eq 2) {
        @($parts[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    else {
        $available = $AvailablePlans | Where-Object { $_.planName -is [string] -and $_.planName -eq $name } |
            Select-Object -First 1
        if (-not $available) {
            throw "The suite has no test plan named '$name'"
        }
        @($available.modules | ForEach-Object { $_.testModule })
    }

    if ($modules -notcontains $KeyRotationModule) {
        return [pscustomobject]@{ Runner = $Specification; KeyRotation = $false }
    }
    $others = @($modules | Where-Object { $_ -ne $KeyRotationModule })
    return [pscustomobject]@{ Runner = "$($parts[0]):$($others -join ',')"; KeyRotation = $true }
}

function Save-Evidence {
    # Written before the containers are removed, since the logs and the screenshots live in them
    if (-not $ResultsPath) {
        return
    }
    docker logs $HostContainer *> (Join-Path $ResultsPath 'host.log')
    docker logs $BrowserContainer *> (Join-Path $ResultsPath 'driver.log')
    docker cp "${BrowserContainer}:$BrowserScreenshots" (Join-Path $ResultsPath 'screenshots') *> $null
}

function Remove-Everything {
    docker rm -f $BrowserContainer 2>$null | Out-Null
    docker rm -f $HostContainer 2>$null | Out-Null
    if ($ComposeFile) {
        docker compose -f $ComposeFile -p $ProjectName down 2>$null | Out-Null
    }
}

function Remove-SuiteClone([string] $Path) {
    # The suite's database writes its files into the clone as its own user, which the user running this script may not
    # be allowed to delete on Linux, so a container removes them first
    docker run --rm -v "${Path}:/suite" $RunnerImage rm -rf /suite/mongo | Out-Null
    Assert-LastExit 'docker run (removing the database files of the previous suite clone)'
    Remove-Item -LiteralPath $Path -Recurse -Force
}

if ($Plan) {
    # Quotes typed around a plan survive pwsh -File and would reach the runner as part of the name
    $Plan = @($Plan | ForEach-Object { $_.Trim().Trim("'", '"') } | Where-Object { $_ })
}
else {
    $Plan = @(Get-Content -LiteralPath $PlanFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') })
}
if (-not $Plan) {
    throw 'No test plan to run: -Plan is empty and so is the plan file'
}
if (-not (Get-Command docker -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'docker was not found on PATH: the suite and the host both run in containers'
}

if ($ResultsPath) {
    # Two runs' evidence in one place cannot be told apart afterwards
    if ((Test-Path -LiteralPath $ResultsPath) -and (-not (Test-Path -LiteralPath $ResultsPath -PathType Container) -or
            (Get-ChildItem -LiteralPath $ResultsPath -Force | Select-Object -First 1))) {
        throw "$ResultsPath is not an empty directory: -ResultsPath has to name a new or empty directory"
    }
    # Created before anything else changes, since the finally block writes the evidence into it
    $ResultsPath = (New-Item -ItemType Directory -Force $ResultsPath).FullName
}

$imageTagBefore = $env:IMAGE_TAG
$ComposeFile = $null
$exitCode = 1
try {
    if (-not $SuitePath) {
        $release = Resolve-SuiteRelease
        $SuitePath = Join-Path ([IO.Path]::GetTempPath()) 'abblix-conformance-suite'
        if (Test-Path -LiteralPath $SuitePath) {
            Remove-SuiteClone $SuitePath
        }
        git clone --quiet --depth 1 --branch $release $SuiteRepository $SuitePath
        Assert-LastExit "git clone (conformance suite $release)"
        # Read by the suite's compose file, which names both of its images by it
        $env:IMAGE_TAG = $release
    }

    $SuitePath = (Resolve-Path -LiteralPath $SuitePath).Path
    foreach ($required in 'docker-compose-prebuilt.yml', 'scripts/run-test-plan.py') {
        if (-not (Test-Path -LiteralPath (Join-Path $SuitePath $required) -PathType Leaf)) {
            throw "$required is missing from $SuitePath`: -SuitePath has to point at a checkout of the conformance suite"
        }
    }
    $ComposeFile = Join-Path $SuitePath 'docker-compose-prebuilt.yml'

    Write-Step "Starting the conformance suite, images $($env:IMAGE_TAG ?? 'latest'), scripts from $SuitePath"
    docker compose -f $ComposeFile -p $ProjectName up -d
    Assert-LastExit 'docker compose up'
    Wait-Until -What 'The conformance suite' -Condition { Test-SuiteReady }

    Write-Step 'Publishing the conformance test host'
    dotnet publish $HostProject -c Release -o $PublishDirectory --nologo -v quiet
    Assert-LastExit 'dotnet publish'

    Write-Step "Starting the host as $HostContainer on $Network"
    docker rm -f $HostContainer 2>$null | Out-Null
    docker run -d --name $HostContainer --network $Network -v "${PublishDirectory}:/app:ro" -w /app `
        $RuntimeImage dotnet $HostAssembly | Out-Null
    Assert-LastExit 'docker run (host)'
    try {
        Wait-Until -What 'The conformance test host' -TimeoutSeconds 60 -Condition { Test-HostReady }
    }
    catch {
        docker logs --tail 50 $HostContainer
        throw
    }

    # A real browser plays the end user for every page the suite publishes, in place of the suite's own headless
    # one, which can neither take the screenshots review modules wait for nor run the session check's hashing
    Write-Step 'Starting the browser driver'
    docker build -q -t $BrowserImage (Join-Path $PSScriptRoot 'browser') | Out-Null
    Assert-LastExit 'docker build (browser driver)'
    $hostSettings = (Get-Content -Raw (Join-Path $HostProject 'appsettings.json') | ConvertFrom-Json).Conformance
    docker rm -f $BrowserContainer 2>$null | Out-Null
    # The screenshots stay inside the container and are copied out at the end, so whoever owns the results
    # directory does not decide whether the driver can write them
    docker run -d --name $BrowserContainer --network $Network --shm-size 1g `
        -e "CONFORMANCE_SERVER=$SuiteUrl" `
        -e "HOST_ORIGIN=$($hostSettings.Issuer)" `
        -e "LOGIN_EMAIL=$($hostSettings.UserEmail)" `
        -e "LOGIN_PASSWORD=$($hostSettings.UserPassword)" `
        -e 'DRIVER_DEADLINE_SECONDS=14400' `
        -e "DRIVER_SCREENSHOT_DIR=$BrowserScreenshots" `
        $BrowserImage | Out-Null
    Assert-LastExit 'docker run (browser driver)'

    # Invoke-RestMethod hands a JSON array on as one object, so it is enumerated here into the plans it holds
    $availablePlans = @(Invoke-RestMethod -Uri "${SuiteUrl}api/plan/available" -SkipCertificateCheck |
        ForEach-Object { $_ })
    $split = @($Plan | ForEach-Object { Split-KeyRotation -Specification $_ -AvailablePlans $availablePlans })
    $keyRotationPlans = @($split | Where-Object KeyRotation | ForEach-Object { ($_.Runner -split ':', 2)[0] })

    # A plan naming every module but one outgrows the command line Windows allows a process, so the runner's
    # arguments go in a file, one per line, which the container reads into its own argument list
    $argumentsDirectory = Join-Path ([IO.Path]::GetTempPath()) 'abblix-conformance-arguments'
    New-Item -ItemType Directory -Force $argumentsDirectory | Out-Null
    $runnerArguments = @('--expected-failures-file', '/config/expected-failures.json')
    $exportMount = @()
    if ($ResultsPath) {
        $exportDirectory = (New-Item -ItemType Directory -Force (Join-Path $ResultsPath 'export')).FullName
        $exportMount = @('-v', "${exportDirectory}:/export")
        $runnerArguments += '--export-dir', '/export'
    }
    foreach ($spec in $split) {
        $runnerArguments += $spec.Runner, '/config/oidcc.json'
    }
    # Line feeds alone: the shell's read keeps a carriage return as part of the argument
    [IO.File]::WriteAllText((Join-Path $argumentsDirectory 'runner.txt'), (($runnerArguments -join "`n") + "`n"))

    Write-Step "Running $($Plan.Count) test plan(s)"
    # The runner's dependencies are installed in a throwaway container rather than on this machine, and each plan
    # specification is one line of the arguments file, so its brackets and spaces are never re-parsed by a shell
    $readArguments = 'set --; while IFS= read -r line; do set -- "$@" "$line"; done < /arguments/runner.txt'
    $runner = @(
        'run', '--rm', '--network', $Network,
        '-v', "${SuitePath}:/suite:ro",
        '-v', "${PSScriptRoot}:/config:ro",
        '-v', "${argumentsDirectory}:/arguments:ro"
    ) + $exportMount + @(
        '-w', '/suite/scripts',
        '-e', "CONFORMANCE_SERVER=$SuiteUrl",
        '-e', "CONFORMANCE_SERVER_MTLS=$SuiteMtlsUrl",
        '-e', 'CONFORMANCE_DEV_MODE=1',
        # The runner gives up after a few modules in a row fail to finish, taking that for a dead server. Here the
        # host is alive by construction, and one broken behavior fails every module that exercises it, one after
        # another - the report on all of them is what the run is for
        '-e', 'CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000',
        $RunnerImage,
        'sh', '-c', "$RunnerInstall && $readArguments && exec python run-test-plan.py `"`$@`""
    )
    docker @runner
    $exitCode = $LASTEXITCODE

    # The key rotation module, kept out of the runner's plans, runs once in each of them with the host rotating its
    # keys between the module's two reads of the key set, as the operator does at certification
    Write-Step "Running the key rotation module in $($keyRotationPlans.Count) plan(s) with the host rotating its keys"
    $rotation = @(
        'run', '--rm', '--network', $Network,
        '-v', "${SuitePath}:/suite:ro",
        '-v', "${PSScriptRoot}:/config:ro",
        '-w', '/suite/scripts',
        '-e', "CONFORMANCE_SERVER=$SuiteUrl",
        '-e', "HOST_ROTATE_URL=$RotateUrl",
        '-e', 'PYTHONPATH=/suite/scripts',
        $RunnerImage,
        'sh', '-c', "$RunnerInstall && exec python /config/rotate-keys.py `"`$@`"", 'sh',
        '/config/oidcc.json'
    ) + $keyRotationPlans
    if ($keyRotationPlans.Count -gt 0) {
        docker @rotation
        if ($LASTEXITCODE -ne 0 -and $exitCode -eq 0) {
            $exitCode = $LASTEXITCODE
        }
    }

    # The driver reports each module it could not drive once it is told to stop
    Write-Step 'Stopping the browser driver'
    docker stop -t 30 $BrowserContainer | Out-Null
    $driverExit = [int](docker wait $BrowserContainer)
    docker logs $BrowserContainer 2>&1 | Select-Object -Last 40
    if ($driverExit -ne 0 -and $exitCode -eq 0) {
        $exitCode = $driverExit
    }
}
finally {
    $env:IMAGE_TAG = $imageTagBefore
    # Collecting the evidence must neither hide why the run failed nor stop the cleanup after it
    try {
        Save-Evidence
    }
    catch {
        Write-Warning "The evidence of the run was not saved in full: $($_.Exception.Message)"
    }
    if ($KeepRunning) {
        Write-Step "Left running: the suite at $SuiteUrl and the host as $HostContainer; stop them with"
        $stopSuite = if ($ComposeFile) { "; docker compose -f `"$ComposeFile`" -p $ProjectName down" } else { '' }
        Write-Host "  docker rm -f $HostContainer$stopSuite"
    }
    else {
        Write-Step 'Removing the host and the suite'
        Remove-Everything
    }
}

exit $exitCode
