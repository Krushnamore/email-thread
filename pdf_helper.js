export async function generatePdf(doc, caseData) {
  const full = JSON.parse(caseData.analysis_json).analysis;

  doc.font('Helvetica-Bold').fontSize(16).text('Email Forensic Investigation Report', { align: 'left' });
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(10);
  doc.text(`Case ID: ${caseData.id}`);
  doc.text(`Generated: ${caseData.created_at}`);
  doc.moveDown();

  const createTable = async (title, rows) => {
    doc.font('Helvetica-Bold').fontSize(12).text(title);
    doc.moveDown(0.5);
    await doc.table({
      headers: [ { label: "", width: 200 }, { label: "", width: 300 } ],
      rows: rows.map(r => [r[0], r[1] || '—']),
    }, {
      prepareHeader: () => doc.font('Helvetica-Bold').fontSize(10),
      prepareRow: (row, indexColumn, indexRow, rectRow) => doc.font('Helvetica').fontSize(9),
      hideHeader: true,
      divider: { header: { disabled: true }, horizontal: { width: 0.5, opacity: 0.5 } },
      padding: 5
    });
    doc.moveDown();
  };

  await createTable('Verdict Summary', [
    ['Threat Score', `${caseData.threat_score} / 100`],
    ['Verdict', caseData.verdict],
    ['Attribution Label', caseData.attribution_label],
    ['Attribution Confidence', `${caseData.attribution_confidence}%`],
    ['Campaign ID', caseData.campaign_id || 'Not correlated with other cases'],
    ['Limited Forensics Mode', caseData.limited_forensics ? 'Yes — plain text only, header checks skipped' : 'False']
  ]);

  let maskedFrom = caseData.from_address;
  if (maskedFrom && maskedFrom.includes('@')) {
    const parts = maskedFrom.split('@');
    if (parts[0].length > 2) {
      maskedFrom = parts[0].substring(0, 2) + '*'.repeat(8) + '@' + parts[1];
    }
  }

  const headerForensics = full.header_forensics || {};
  const returnPath = headerForensics.return_path?.return_path_domain || '—';

  await createTable('Sender Information', [
    ['From (masked)', maskedFrom],
    ['From Display Name', '—'],
    ['From Domain', caseData.sender_domain],
    ['Return-Path Domain', returnPath],
    ['Subject', caseData.subject],
    ['Date', '—'] // Optional: extract Date if available
  ]);

  doc.font('Helvetica-Bold').fontSize(12).text('Authentication (SPF / DKIM / DMARC)');
  doc.moveDown(0.5);
  if (!full.header_forensics.authentication.available || (full.header_forensics.authentication.spf === 'neutral' && full.header_forensics.authentication.dkim === 'neutral' && full.header_forensics.authentication.dmarc === 'neutral')) {
    doc.font('Helvetica').fontSize(10).text('Authentication headers unavailable in this input mode.');
  } else {
    doc.font('Helvetica').fontSize(10).text(`SPF: ${full.header_forensics.authentication.spf} | DKIM: ${full.header_forensics.authentication.dkim} | DMARC: ${full.header_forensics.authentication.dmarc}`);
  }
  doc.moveDown(1.5);

  const intel = full.intel || {};
  const geoip = intel.geoip || {};
  await createTable('Network & Geolocation Intelligence', [
    ['Earliest Public Relay IP', intel.earliest_public_ip || '—'],
    ['Probable Country', geoip.country || '—'],
    ['Probable City', geoip.city || '—'],
    ['ISP / Org', geoip.isp || '—'],
    ['Location Disclaimer', geoip.country ? 'Probable sending infrastructure location — NOT a confirmed attacker location.' : '—'],
    ['Tor Exit Node', intel.is_tor_exit_node ? 'True' : '—'],
    ['Known VPN Provider', intel.is_known_vpn ? 'True' : 'False'],
    ['Generic Cloud Hosting', intel.is_cloud_hosting ? 'True' : 'False']
  ]);

  const whois = intel.whois || {};
  await createTable('Domain (WHOIS) Intelligence', [
    ['Registrar', whois.registrar || '—'],
    ['Creation Date', whois.creation_date || '—'],
    ['Domain Age (days)', whois.age_days || '—']
  ]);

  doc.font('Helvetica-Bold').fontSize(12).text('Relay Path (Oldest Hop First)');
  doc.moveDown(0.5);
  const hops = headerForensics.relay_chain?.hops || [];
  if (hops.length === 0) {
    doc.font('Helvetica').fontSize(10).text('No relay chain available for this input mode.');
  } else {
    hops.forEach(hop => {
      doc.font('Helvetica').fontSize(10).text(`Hop ${hop.hop_index}: from ${hop.from_host || 'unknown'} by ${hop.by_host || 'unknown'} [${hop.ip || 'unknown'}]`);
    });
  }
  doc.moveDown(1.5);

  doc.addPage();
  
  doc.font('Helvetica-Bold').fontSize(12).text('Scoring Rationale');
  doc.moveDown(0.5);
  if (full.scoring.reasons && full.scoring.reasons.length > 0) {
    full.scoring.reasons.forEach(r => doc.font('Helvetica').fontSize(10).text(`• ${r}`));
  } else {
    doc.font('Helvetica').fontSize(10).text('None');
  }
  doc.moveDown(1.5);

  doc.font('Helvetica-Bold').fontSize(12).text('Machine Learning Assessment');
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(10).text(full.scoring.ml_explanation || 'No explanation available');
  doc.moveDown();
  if (full.scoring.ml_top_features && full.scoring.ml_top_features.length > 0) {
    doc.font('Helvetica').fontSize(10).text('Top phrases driving this classification:');
    full.scoring.ml_top_features.forEach(f => doc.text(`• '${f[0]}' (weight ${f[1]})`));
  }
  doc.moveDown(1.5);

  doc.font('Helvetica-Bold').fontSize(12).text('Recommended Actions');
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(10).text(full.recommendations.summary || '');
  doc.moveDown(0.5);
  if (full.recommendations.actions && full.recommendations.actions.length > 0) {
    full.recommendations.actions.forEach(a => doc.font('Helvetica').fontSize(10).text(`• ${a}`));
  }
  doc.moveDown(1.5);

  await createTable('Evidence Integrity', [
    ['Evidence SHA-256', caseData.evidence_sha256]
  ]);

  doc.addPage();
  doc.font('Helvetica-Bold').fontSize(12).text('Attribution Limitations');
  doc.moveDown(0.5);
  doc.font('Helvetica').fontSize(10).text('Attribution Limitations: The indicators in this report (IP addresses, geolocation, relay hops, and domain intelligence) describe observed sending infrastructure only. An IP address or hosting location is not equivalent to the identity of a person. Email headers, including Received and Authentication-Results headers, can be forged or manipulated by a sufficiently capable actor. All conclusions in this report should be treated as investigative leads requiring further corroboration, not as definitive proof of identity or location.');

  doc.end();
}
