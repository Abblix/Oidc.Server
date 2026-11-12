#Requires -Version 7.3
<#
.SYNOPSIS
Runs OpenID Foundation conformance test plans against the conformance test host, locally and without a browser.

.DESCRIPTION
Starts the suite from its published images, publishes the test host and runs it as a container on the suite's
network, runs the suite's own plan runner, then removes what it started. The exit code is the runner's: zero when
every module passed or waits only for a reviewer to look at a screenshot, non-zero on any unexpected failure.

.PARAMETER SuitePath
A checkout of https://gitlab.com/openid/conformance-suite. Its runner script and compose file are used as they are.

.PARAMETER Plan
Test plans to run, each with its variants and optionally a module list after a colon, in the runner's syntax.
Several are passed from a PowerShell prompt or with the call operator; under pwsh -File a list arrives as one
string, so there one plan goes here and several go in a file named by -PlanFile.

.PARAMETER PlanFile
A file with one plan per line, lines starting with # ignored. Used when -Plan is not given; by default the plans
Abblix OIDC Server is certified against, certified-plans.txt.

.PARAMETER KeepRunning
Leaves the suite and the host running afterwards, so a failed module can be opened in the suite's web interface.

.EXAMPLE
./conformance/run.ps1 -SuitePath ../conformance-suite

.EXAMPLE
./conformance/run.ps1 -SuitePath ../conformance-suite -Plan 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]:oidcc-server'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SuitePath,

    [string[]] $Plan,

    [string] $PlanFile = (Join-Path $PSScriptRoot 'certified-plans.txt'),

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

$RuntimeImage = 'mcr.microsoft.com/dotnet/aspnet:11.0'
$ProbeImage = 'curlimages/curl:8.10.1'
$RunnerImage = 'python:3.12-slim'

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$HostProject = Join-Path $RepositoryRoot 'tests/Abblix.Oidc.Server.MinimalApi.Conformance.TestHost'
$HostAssembly = 'Abblix.Oidc.Server.MinimalApi.Conformance.TestHost.dll'
$PublishDirectory = Join-Path ([IO.Path]::GetTempPath()) 'abblix-conformance-host'

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

function Remove-Everything {
    docker rm -f $HostContainer 2>$null | Out-Null
    docker compose -f $ComposeFile -p $ProjectName down 2>$null | Out-Null
}

$SuitePath = (Resolve-Path -LiteralPath $SuitePath).Path
$ComposeFile = Join-Path $SuitePath 'docker-compose-prebuilt.yml'
$RunnerScript = Join-Path $SuitePath 'scripts/run-test-plan.py'
foreach ($required in $ComposeFile, $RunnerScript) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "$required is missing: -SuitePath has to point at a checkout of the conformance suite"
    }
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

$exitCode = 1
try {
    Write-Step 'Starting the conformance suite from its published images'
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

    Write-Step "Running $($Plan.Count) test plan(s)"
    # The runner's dependencies are installed in a throwaway container rather than on this machine, and the plan
    # specifications reach it as separate arguments, so their brackets and spaces are never re-parsed by a shell
    $runner = @(
        'run', '--rm', '--network', $Network,
        '-v', "${SuitePath}:/suite:ro",
        '-v', "${PSScriptRoot}:/config:ro",
        '-w', '/suite/scripts',
        '-e', "CONFORMANCE_SERVER=$SuiteUrl",
        '-e', "CONFORMANCE_SERVER_MTLS=$SuiteMtlsUrl",
        '-e', 'CONFORMANCE_DEV_MODE=1',
        # The runner gives up after a few modules in a row fail to finish, taking that for a dead server. Here the
        # host is alive by construction, and one broken behavior fails every module that exercises it, one after
        # another - the report on all of them is what the run is for
        '-e', 'CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000',
        $RunnerImage,
        'sh', '-c', 'pip install -q --root-user-action=ignore -r requirements.txt && exec python run-test-plan.py "$@"', 'sh',
        # Failures this setup cannot avoid, each with its reason, so they neither fail the run nor hide a new one
        '--expected-failures-file', '/config/expected-failures.json'
    )
    foreach ($spec in $Plan) {
        $runner += $spec, '/config/oidcc.json'
    }
    docker @runner
    $exitCode = $LASTEXITCODE
}
finally {
    if ($KeepRunning) {
        Write-Step "Left running: the suite at $SuiteUrl and the host as $HostContainer; stop them with"
        Write-Host "  docker rm -f $HostContainer; docker compose -f `"$ComposeFile`" -p $ProjectName down"
    }
    else {
        Write-Step 'Removing the host and the suite'
        Remove-Everything
    }
}

exit $exitCode
