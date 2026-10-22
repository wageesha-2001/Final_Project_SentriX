export type SyncMode = 'local' | 'remote' | 'both'

export interface CommunityDbConfig {
  enabled: boolean
  localPath: string
  remoteUrl: string
  syncMode: SyncMode
  githubToken: string
}

/**
 * Accept the GitHub page link people usually copy
 * (https://github.com/<owner>/<repo>/blob/<branch>/<path>) and turn it into
 * the raw file link (https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>).
 */
export function normalizeRemoteUrl(url: string): string {
  const m = url.match(/^https:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+)\/(?:blob|raw)\/(.+?)\/?(?:[?#].*)?$/)
  return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}` : url
}

export function getCommunityDbConfig(): CommunityDbConfig {
  const mode = (process.env.COMMUNITY_VULN_DB_SYNC_MODE ?? 'local').trim().toLowerCase()
  return {
    enabled: (process.env.COMMUNITY_VULN_DB_ENABLED ?? 'true').trim().toLowerCase() !== 'false',
    localPath: (process.env.COMMUNITY_VULN_DB_LOCAL_PATH ?? '').trim() || 'data/vulnerabilities.txt',
    remoteUrl: normalizeRemoteUrl((process.env.COMMUNITY_VULN_DB_REMOTE_URL ?? '').trim()),
    syncMode: mode === 'remote' || mode === 'both' ? mode : 'local',
    // Only needed when the GitHub repo is private (fine-grained PAT with Contents: read-only)
    githubToken: (process.env.COMMUNITY_VULN_DB_GITHUB_TOKEN ?? '').trim(),
  }
}
