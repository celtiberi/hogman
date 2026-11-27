// Pure invite/device link parsing and shell command builders for /join.
// Imported by join.js in the browser and directly by CI/Node tests.

const SAFE_TOKEN_RE = /^[a-zA-Z0-9._-]+$/;
const SAFE_HOST_RE = /^[a-zA-Z0-9._:-]+$/;

export function parseJoinHash(rawHash, host) {
  const hash = String(rawHash || '').replace(/^#/, '');
  const q = new URLSearchParams(hash);
  const t = q.get('t');
  const k = q.get('k');
  const fp = q.get('fp');

  if (fp) {
    return {
      ok: false,
      error: 'This link is from an older release and is no longer valid. Ask whoever sent it for a fresh one.',
    };
  }
  if (!(t || k)) {
    return {
      ok: false,
      error: 'This link is incomplete. Ask whoever sent it for a fresh one, and copy it whole.',
    };
  }
  if (t && k) {
    return {
      ok: false,
      error: 'This link is invalid. Ask whoever sent it for a fresh one.',
    };
  }
  if ((t && !SAFE_TOKEN_RE.test(t)) ||
      (k && !SAFE_TOKEN_RE.test(k)) ||
      !SAFE_HOST_RE.test(String(host || ''))) {
    return {
      ok: false,
      error: 'This link contains unexpected characters. Ask whoever sent it for a fresh one.',
    };
  }

  // A server link (for=share) only puts something in the pen with `share`;
  // it never joins a whole computer.
  const forShare = !t && q.get('for') === 'share';
  const kind = t ? 'invite' : (forShare ? 'share' : 'device');
  const cleanLink = `https://${host}/join#${t ? 't=' + t : 'k=' + k}${forShare ? '&for=share' : ''}`;
  return { ok: true, kind, forShare, cleanLink };
}

export function buildStartCommand(host, cleanLink, args = '') {
  const quoted = `'${cleanLink}'`;
  return `curl -fsSL --proto '=https' --proto-redir '=https' https://${host}/start | HOGMAN_EXPECTED_HOST='${host}' sh -s -- ${quoted}${args ? ' ' + args : ''}`;
}

export function buildManualCommand(host, cleanLink, verb = '') {
  const quoted = `'${cleanLink}'`;
  return `curl -fsSL --proto '=https' --proto-redir '=https' -o hogman "https://${host}/join/dl/hogman-$(uname -s)-$(uname -m)" && chmod +x hogman && ./hogman ${verb}${quoted}`;
}

export function buildWindowsStartCommand(host, cleanLink, args = []) {
  const extra = args.length ? ' ' + args.map(a => `'${a}'`).join(' ') : '';
  return `$s = curl.exe -fsSL --proto '=https' --proto-redir '=https' 'https://${host}/start.ps1' | Out-String; if ($LASTEXITCODE -eq 0) { & ([scriptblock]::Create($s)) -ExpectedHost '${host}' '${cleanLink}'${extra} }`;
}

export function buildWindowsManualCommand(host, cleanLink, verb = '') {
  return `$a = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }; curl.exe -fsSL --proto '=https' --proto-redir '=https' -o hogman.exe "https://${host}/join/dl/hogman-windows-$a.exe"; if ($LASTEXITCODE -eq 0) { .\\hogman.exe ${verb}'${cleanLink}' }`;
}

export function buildJoinCommands({ host, cleanLink, forShare = false, isWork = false }) {
  if (!forShare) {
    return {
      startCmd: buildStartCommand(host, cleanLink, ''),
      manualCmd: buildManualCommand(host, cleanLink, ''),
      winStartCmd: buildWindowsStartCommand(host, cleanLink, []),
      winManualCmd: buildWindowsManualCommand(host, cleanLink, ''),
    };
  }
  const shareTokens = isWork ? ['share', 'cooler-1', 'http://192.168.1.40'] : ['share', 'blog', '8080'];
  const shareArgs = shareTokens.join(' ');
  return {
    startCmd: buildStartCommand(host, cleanLink, shareArgs),
    manualCmd: buildManualCommand(host, cleanLink, `${shareArgs} `),
    winStartCmd: buildWindowsStartCommand(host, cleanLink, shareTokens),
    winManualCmd: buildWindowsManualCommand(host, cleanLink, `${shareArgs} `),
  };
}
