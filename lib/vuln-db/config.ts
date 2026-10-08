export type SyncMode = 'local' | 'remote' | 'both'

export interface CommunityDbConfig {
  enabled: boolean
  localPath: string
  remoteUrl: string
  syncMode: SyncMode
}

export function getCommunityDbConfig(): CommunityDbConfig {
  const mode = (process.env.COMMUNITY_VULN_DB_SYNC_MODE ?? 'local').trim().toLowerCase()
  return {
    enabled: (process.env.COMMUNITY_VULN_DB_ENABLED ?? 'true').trim().toLowerCase() !== 'false',
    localPath: (process.env.COMMUNITY_VULN_DB_LOCAL_PATH ?? '').trim() || 'data/vulnerabilities.txt',
    remoteUrl: (process.env.COMMUNITY_VULN_DB_REMOTE_URL ?? '').trim(),
    syncMode: mode === 'remote' || mode === 'both' ? mode : 'local',
  }
}
