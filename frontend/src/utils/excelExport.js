import * as XLSX from 'xlsx';

/**
 * Client-side multi-sheet Excel export helper for Email OSINT data.
 * Produces a formatted .xlsx workbook.
 */
export function exportEmailIntelToExcel(data) {
  if (!data) return;

  const email = data.email || 'investigation';
  const identity = data.identity || {};
  const reputation = data.reputation || {};
  const dnsData = data.dns || {};
  const commits = data.github_commits?.commits || [];
  const codeRefs = data.github_code?.references || [];
  const webpages = identity.public_webpages || data.public_web_pages?.pages || [];
  const socials = identity.social_profiles || [];
  const xonData = data.xposedornot || {};
  const breachesList = xonData.breaches || data.breaches || [];

  const wb = XLSX.utils.book_new();

  // 1. Sheet: Identity Summary
  const summaryRows = [
    ['OSINT-to-Attack-Path — Email Intelligence Dossier', ''],
    ['Target Email', email],
    ['Investigation Date', data.lookup_timestamp || new Date().toISOString()],
    ['Sources Queried', (data.sources_queried || []).join(', ')],
    ['Sources Responded', (data.sources_successful || []).join(', ')],
    ['', ''],
    ['IDENTITY ATTRIBUTE', 'VALUE'],
    ['Full Name', identity.name || 'Not Identified'],
    ['Associated Username', identity.username || 'Not Identified'],
    ['Domain', identity.domain || ''],
    ['Company / Organization', identity.company || 'Not Disclosed'],
    ['Location', identity.location || 'Not Disclosed'],
    ['Bio / Role Description', identity.bio || 'N/A'],
    ['Mail Provider', identity.mail_provider || 'Standard DNS Mail Exchange'],
    ['XposedOrNot Breach Status', xonData.breached ? `BREACHED (${breachesList.length} breach exposure(s))` : 'CLEAN (No breaches detected)'],
    ['Breach Risk Score', `${xonData.risk_score || 0}/10 (${xonData.risk_label || 'Clean'})`],
    ['Public Pastes Count', `${xonData.pastes_count || 0} paste(s)`],
    ['Reputation Score', String(reputation.reputation || 'Unknown').toUpperCase()],
    ['Suspicious Flag', reputation.suspicious ? 'YES (Suspicious)' : 'NO (Clean)'],
    ['Deliverable Status', reputation.deliverable ? 'Deliverable' : 'Undeliverable / Unknown'],
    ['Credentials Leaked', reputation.credentials_leaked ? 'YES (Found in Leaks)' : 'NO'],
    ['Data Breach Record', reputation.data_breach ? 'YES (Found in Breach Dumps)' : 'NO'],
    ['First Seen Date', reputation.first_seen || 'Unknown'],
    ['Last Seen Date', reputation.last_seen || 'Unknown'],
    ['Avatar URL', identity.avatar_url || 'None'],
  ];
  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
  wsSummary['!cols'] = [{ wch: 28 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Identity Summary');

  // 2. Sheet: Security Posture & Risk
  const posture = data.security_posture || {};
  const nist = posture.nist_assessment || {};
  const postureRows = [
    ['OSINT-to-Attack-Path — Security Posture & Threat Assessment', ''],
    ['Target Email', email],
    ['Risk Scoring Standard', nist.standard || 'NIST SP 800-30 Rev. 1'],
    ['Threat Event Likelihood', `${nist.threat_likelihood ?? 'N/A'} / 10 (${nist.likelihood_tier || ''})`],
    ['Threat Event Impact', `${nist.threat_impact ?? 'N/A'} / 10 (${nist.impact_tier || ''})`],
    ['Composite Risk Score', `${posture.composite_score || 0} / 100 (Grade ${posture.grade || 'C'})`],
    ['Security Health Rating', `${posture.health_score || 100} / 100`],
    ['Threat Level', posture.risk_level || 'UNKNOWN'],
    ['Defensive Verdict', posture.verdict || 'N/A'],
    ['', ''],
    ['SECURITY DIMENSION', 'RISK SCORE', 'STATUS', 'SUMMARY ANALYSIS'],
  ];

  const pillars = posture.pillars || {};
  Object.keys(pillars).forEach(k => {
    const p = pillars[k];
    postureRows.push([p.name || k, `${p.score || 0}/100`, p.status || 'N/A', p.description || '']);
  });

  postureRows.push(['', '', '', '']);
  postureRows.push(['CATEGORY', 'CONTROL EVALUATED', 'OBSERVED VALUE', 'STATUS', 'DETAILS', 'MITIGATION']);

  (posture.posture_matrix || []).forEach(c => {
    postureRows.push([
      c.category || '',
      c.control || '',
      String(c.value || ''),
      c.status || 'PASS',
      c.detail || '',
      c.recommendation || '',
    ]);
  });

  postureRows.push(['', '', '', '', '', '']);
  postureRows.push(['ATTACK SCENARIO', 'MITRE ATT&CK', 'PROBABILITY', 'IMPACT', 'KILL CHAIN', 'MITIGATION']);

  (posture.attack_scenarios || []).forEach(sc => {
    postureRows.push([
      sc.title || '',
      `${sc.mitre_technique || ''} (${sc.mitre_name || ''})`,
      sc.probability || 'MEDIUM',
      sc.impact || 'HIGH',
      (sc.attack_steps || []).join(' -> '),
      sc.mitigation || '',
    ]);
  });

  postureRows.push(['', '', '', '', '', '']);
  postureRows.push(['PRIORITY', 'CATEGORY', 'HARDENING OBJECTIVE', 'REMEDIATION ACTION', 'EFFORT']);

  (posture.defensive_playbook || []).forEach(pb => {
    postureRows.push([
      pb.priority || 'P2 - High',
      pb.category || 'General',
      pb.title || '',
      pb.remediation_cmd || pb.description || '',
      pb.effort || 'LOW',
    ]);
  });

  const wsPosture = XLSX.utils.aoa_to_sheet(postureRows);
  wsPosture['!cols'] = [{ wch: 25 }, { wch: 32 }, { wch: 20 }, { wch: 14 }, { wch: 50 }, { wch: 45 }];
  XLSX.utils.book_append_sheet(wb, wsPosture, 'Security Posture & Risk');

  // 2. Sheet: Data Breaches (XposedOrNot)
  const breachRows = [
    ['BREACH NAME', 'TARGET DOMAIN', 'INDUSTRY', 'BREACH DATE', 'PASSWORD RISK', 'EXPOSED RECORDS', 'EXPOSED DATA', 'INCIDENT DETAILS'],
  ];
  if (breachesList.length > 0) {
    breachesList.forEach(b => {
      const xData = b.xposed_data || [];
      const xDataStr = Array.isArray(xData) ? xData.join(', ') : String(xData);
      breachRows.push([
        b.breach || 'Unknown Breach',
        b.domain || 'N/A',
        b.industry || 'General',
        b.xposed_date || 'Unknown',
        String(b.password_risk || 'UNKNOWN').toUpperCase(),
        b.xposed_records || 0,
        xDataStr || 'Credentials',
        b.details || 'No details available.',
      ]);
    });
  } else {
    breachRows.push(['No data breaches detected for this email in XposedOrNot.', '', '', '', '', '', '', '']);
  }
  const wsBreaches = XLSX.utils.aoa_to_sheet(breachRows);
  wsBreaches['!cols'] = [{ wch: 28 }, { wch: 24 }, { wch: 24 }, { wch: 14 }, { wch: 18 }, { wch: 16 }, { wch: 35 }, { wch: 60 }];
  XLSX.utils.book_append_sheet(wb, wsBreaches, 'Data Breaches (XON)');

  // 3. Sheet: Public Webpages
  const webpageRows = [
    ['PAGE TITLE', 'PUBLIC WEBPAGE URL', 'SNIPPET / CONTEXT', 'SOURCE'],
  ];
  if (webpages.length > 0) {
    webpages.forEach(p => {
      webpageRows.push([
        p.title || 'Public Webpage',
        p.url || '',
        p.snippet || '',
        p.source || 'Public Web Search',
      ]);
    });
  } else {
    webpageRows.push(['No direct public webpages indexed for this email.', '', '', '']);
  }
  const wsWeb = XLSX.utils.aoa_to_sheet(webpageRows);
  wsWeb['!cols'] = [{ wch: 35 }, { wch: 50 }, { wch: 60 }, { wch: 24 }];
  XLSX.utils.book_append_sheet(wb, wsWeb, 'Public Webpages');

  // 3. Sheet: GitHub Commits
  const commitRows = [
    ['REPOSITORY', 'AUTHOR NAME', 'COMMIT DATE', 'MESSAGE', 'COMMIT URL'],
  ];
  if (commits.length > 0) {
    commits.forEach(c => {
      commitRows.push([
        c.repo || '',
        c.author_name || '',
        c.date || '',
        c.message || '',
        c.commit_url || '',
      ]);
    });
  } else {
    commitRows.push(['No public GitHub commits found with author-email matching target.', '', '', '', '']);
  }
  const wsCommits = XLSX.utils.aoa_to_sheet(commitRows);
  wsCommits['!cols'] = [{ wch: 30 }, { wch: 22 }, { wch: 22 }, { wch: 50 }, { wch: 50 }];
  XLSX.utils.book_append_sheet(wb, wsCommits, 'GitHub Commits');

  // 4. Sheet: Code References
  const codeRows = [
    ['FILE NAME', 'REPOSITORY', 'FILE PATH', 'FILE URL'],
  ];
  if (codeRefs.length > 0) {
    codeRefs.forEach(cd => {
      codeRows.push([
        cd.file || '',
        cd.repo || '',
        cd.path || '',
        cd.file_url || '',
      ]);
    });
  } else {
    codeRows.push(['No public code search occurrences discovered.', '', '', '']);
  }
  const wsCode = XLSX.utils.aoa_to_sheet(codeRows);
  wsCode['!cols'] = [{ wch: 25 }, { wch: 30 }, { wch: 35 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsCode, 'Code References');

  // 5. Sheet: Mail Infrastructure
  const mxRows = [
    ['CONFIGURATION ITEM', 'DETAIL / VALUE'],
    ['Target Domain', dnsData.domain || ''],
    ['Mail Provider', dnsData.mail_provider || 'Unknown'],
    ['SPF Record TXT', dnsData.spf_record || 'None'],
    ['SPF Enforcement', dnsData.spf_status || 'None'],
    ['DMARC Record TXT', dnsData.dmarc_record || 'None'],
    ['DMARC Policy', dnsData.dmarc_policy || 'None'],
    ['', ''],
    ['PRIORITY', 'MX EXCHANGE SERVER HOST'],
  ];
  const mxList = dnsData.mx_records || [];
  if (mxList.length > 0) {
    mxList.forEach(m => mxRows.push([m.priority, m.exchange]));
  } else {
    mxRows.push(['N/A', 'No MX records discovered']);
  }
  const wsMx = XLSX.utils.aoa_to_sheet(mxRows);
  wsMx['!cols'] = [{ wch: 25 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsMx, 'Mail Infrastructure');

  // 6. Sheet: Social Profiles
  const socialRows = [
    ['PLATFORM', 'USERNAME / HANDLE', 'PROFILE URL'],
  ];
  if (socials.length > 0) {
    socials.forEach(s => {
      socialRows.push([s.platform || '', s.username || '—', s.url || '—']);
    });
  } else {
    socialRows.push(['No social profile links discovered.', '', '']);
  }
  const wsSocial = XLSX.utils.aoa_to_sheet(socialRows);
  wsSocial['!cols'] = [{ wch: 20 }, { wch: 25 }, { wch: 50 }];
  XLSX.utils.book_append_sheet(wb, wsSocial, 'Social Profiles');

  // Trigger download
  const cleanName = email.replace(/[^a-zA-Z0-9_.-]/g, '_');
  XLSX.writeFile(wb, `Email_Intel_${cleanName}.xlsx`);
}

/**
 * Client-side multi-sheet Excel export helper for Username OSINT data.
 * Produces a formatted .xlsx workbook.
 */
export function exportUsernameIntelToExcel(data) {
  if (!data) return;

  const username = data.username || 'identity';
  const profile = data.profile || {};
  const posture = data.security_posture || {};
  const repos = data.repos?.repos || [];
  const probes = data.platform_probes || [];
  const commits = data.events?.commits || [];
  const uncoveredEmails = data.uncovered_emails || [];
  const breachedEmails = data.breached_emails || [];
  const webpages = data.web_pages?.pages || [];

  const wb = XLSX.utils.book_new();

  // 1. Sheet: Identity Summary
  const summaryRows = [
    ['OSINT-to-Attack-Path — Username Intelligence Dossier', ''],
    ['Target Username', `@${username}`],
    ['Investigation Date', data.lookup_timestamp || new Date().toISOString()],
    ['Sources Queried', (data.sources_queried || []).join(', ')],
    ['Sources Responded', (data.sources_successful || []).join(', ')],
    ['', ''],
    ['IDENTITY ATTRIBUTE', 'VALUE'],
    ['Full Name', profile.name || 'Not Identified'],
    ['Bio / Role Description', profile.bio || 'N/A'],
    ['Company / Organization', profile.company || 'Not Disclosed'],
    ['Location', profile.location || 'Not Disclosed'],
    ['Website / Blog', profile.blog || 'None'],
    ['Twitter / X', profile.twitter_username ? `@${profile.twitter_username}` : 'None'],
    ['GitHub Profile', profile.profile_url || `https://github.com/${username}`],
    ['Public Repositories', profile.public_repos || 0],
    ['Public Gists', profile.public_gists || 0],
    ['Followers / Following', `${profile.followers || 0} / ${profile.following || 0}`],
    ['Platforms Discovered', `${data.platforms_found_count || 0} Online Services`],
    ['Uncovered Commit Emails', uncoveredEmails.length > 0 ? uncoveredEmails.join(', ') : 'None Discovered'],
    ['Security Posture Grade', `Grade ${posture.grade || 'C'} (${posture.risk_level || 'MODERATE RISK'})`],
    ['Composite Threat Index', `${posture.composite_score || 0} / 100`],
    ['Resilience Health Score', `${posture.health_score || 0} %`],
  ];
  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
  wsSummary['!cols'] = [{ wch: 28 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Identity Summary');

  // 2. Sheet: Security Posture & Controls Matrix
  const nistUser = posture.nist_assessment || {};
  const postureRows = [
    ['OSINT-to-Attack-Path — Security Posture Assessment', '', '', '', ''],
    ['Target Handle', `@${username}`, '', '', ''],
    ['Risk Scoring Standard', nistUser.standard || 'NIST SP 800-30 Rev. 1', '', '', ''],
    ['Threat Event Likelihood', `${nistUser.threat_likelihood ?? 'N/A'} / 10 (${nistUser.likelihood_tier || ''})`, '', '', ''],
    ['Threat Event Impact', `${nistUser.threat_impact ?? 'N/A'} / 10 (${nistUser.impact_tier || ''})`, '', '', ''],
    ['Composite Risk Score', `${posture.composite_score || 0} / 100 (Grade ${posture.grade || 'C'})`, '', '', ''],
    ['Resilience Health', `${posture.health_score || 0} %`, '', '', ''],
    ['Threat Level', posture.risk_level || 'MODERATE', '', '', ''],
    ['Operations Verdict', posture.verdict || '', '', '', ''],
    ['', '', '', '', ''],
    ['CATEGORY', 'CONTROL', 'OBSERVED VALUE', 'STATUS', 'RECOMMENDATION'],
  ];
  const matrix = posture.posture_matrix || [];
  matrix.forEach(m => {
    postureRows.push([
      m.category || '',
      m.control || '',
      m.value || '',
      m.status || '',
      m.recommendation || '',
    ]);
  });
  const wsPosture = XLSX.utils.aoa_to_sheet(postureRows);
  wsPosture['!cols'] = [{ wch: 22 }, { wch: 28 }, { wch: 30 }, { wch: 12 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsPosture, 'Controls Matrix');

  // 3. Sheet: Attack Scenarios
  const scenarioRows = [
    ['SCENARIO TITLE', 'MITRE TECHNIQUE', 'SEVERITY', 'IMPACT', 'DEFENSIVE MITIGATION'],
  ];
  const scenarios = posture.attack_scenarios || [];
  if (scenarios.length > 0) {
    scenarios.forEach(sc => {
      scenarioRows.push([
        sc.title || '',
        sc.mitre_technique || '',
        sc.severity || '',
        sc.impact || '',
        sc.mitigation || '',
      ]);
    });
  } else {
    scenarioRows.push(['No critical attack scenarios triggered.', '', '', '', '']);
  }
  const wsScenarios = XLSX.utils.aoa_to_sheet(scenarioRows);
  wsScenarios['!cols'] = [{ wch: 35 }, { wch: 22 }, { wch: 12 }, { wch: 18 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsScenarios, 'Attack Scenarios');

  // 4. Sheet: Cross-Platform Accounts
  const probeRows = [
    ['PLATFORM', 'CATEGORY', 'STATUS', 'PROFILE URL', 'HTTP STATUS'],
  ];
  if (probes.length > 0) {
    probes.forEach(p => {
      probeRows.push([
        p.platform || '',
        p.category || '',
        p.status || '',
        p.profile_url || '',
        p.status_code || '',
      ]);
    });
  }
  const wsProbes = XLSX.utils.aoa_to_sheet(probeRows);
  wsProbes['!cols'] = [{ wch: 20 }, { wch: 24 }, { wch: 14 }, { wch: 50 }, { wch: 12 }];
  XLSX.utils.book_append_sheet(wb, wsProbes, 'Platform Accounts');

  // 5. Sheet: Repositories & Commits
  const repoRows = [
    ['REPOSITORY NAME', 'PRIMARY LANGUAGE', 'STARS', 'FORKS', 'DESCRIPTION', 'URL'],
  ];
  if (repos.length > 0) {
    repos.forEach(r => {
      repoRows.push([
        r.name || '',
        r.language || '',
        r.stars || 0,
        r.forks || 0,
        r.description || '',
        r.url || '',
      ]);
    });
  }
  const wsRepos = XLSX.utils.aoa_to_sheet(repoRows);
  wsRepos['!cols'] = [{ wch: 25 }, { wch: 18 }, { wch: 10 }, { wch: 10 }, { wch: 45 }, { wch: 50 }];
  XLSX.utils.book_append_sheet(wb, wsRepos, 'Repositories');

  // 6. Sheet: Discovered Emails & Breaches
  const emailRows = [
    ['DISCOVERED EMAIL', 'BREACH STATUS', 'BREACH COUNT', 'INCIDENTS'],
  ];
  if (uncoveredEmails.length > 0) {
    uncoveredEmails.forEach(em => {
      const bInfo = (breachedEmails || []).find(b => b.email === em);
      emailRows.push([
        em,
        bInfo?.breached ? 'BREACHED' : 'CLEAN / NO EXPOSURE',
        bInfo?.breach_count || 0,
        (bInfo?.breaches || []).join(', ') || 'No breach records found',
      ]);
    });
  } else {
    emailRows.push(['No commit emails uncovered.', '', '', '']);
  }
  const wsEmails = XLSX.utils.aoa_to_sheet(emailRows);
  wsEmails['!cols'] = [{ wch: 32 }, { wch: 22 }, { wch: 14 }, { wch: 55 }];
  XLSX.utils.book_append_sheet(wb, wsEmails, 'Discovered Emails');

  // 7. Sheet: Web Mentions
  const webRows = [
    ['PAGE TITLE', 'URL', 'SNIPPET'],
  ];
  if (webpages.length > 0) {
    webpages.forEach(pg => {
      webRows.push([
        pg.title || '',
        pg.url || '',
        pg.snippet || '',
      ]);
    });
  } else {
    webRows.push(['No public web mentions indexed.', '', '']);
  }
  const wsWeb = XLSX.utils.aoa_to_sheet(webRows);
  wsWeb['!cols'] = [{ wch: 35 }, { wch: 55 }, { wch: 60 }];
  XLSX.utils.book_append_sheet(wb, wsWeb, 'Web Mentions');

  // Trigger download
  const cleanName = username.replace(/[^a-zA-Z0-9_.-]/g, '_');
  XLSX.writeFile(wb, `Username_Intel_${cleanName}.xlsx`);
}

