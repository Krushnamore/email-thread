// pdf_helper.js
// Builds the Email Forensic Investigation Report PDF onto an existing
// PDFDocument (`doc`). The caller (server.js) creates the doc, sets the
// response headers, pipes it to res, then calls generatePdf(doc, caseData).
// This file calls doc.end() itself once done.

const COLORS = {
  ink: '#1a1a1a',
  muted: '#5f6368',
  line: '#e2e5e9',
  bandBg: '#0f1b2d',
  bandText: '#ffffff',
  low: '#1a7f37',
  medium: '#b98900',
  high: '#c0392b',
  critical: '#8e1c1c',
};

function verdictColor(verdict) {
  switch ((verdict || '').toUpperCase()) {
    case 'LOW': return COLORS.low;
    case 'MEDIUM': return COLORS.medium;
    case 'HIGH': return COLORS.high;
    case 'CRITICAL': return COLORS.critical;
    default: return COLORS.muted;
  }
}

// Adds a new page if `height` more points won't fit before the bottom margin.
function ensureSpace(doc, height) {
  const bottom = doc.page.height - doc.page.margins.bottom;
  if (doc.y + height > bottom) {
    doc.addPage();
  }
}

function sectionTitle(doc, text) {
  ensureSpace(doc, 50);
  doc.moveDown(0.7);
  doc
    .fillColor(COLORS.ink)
    .font('Helvetica-Bold')
    .fontSize(12)
    .text(text.toUpperCase(), { characterSpacing: 0.4 });
  const y = doc.y + 2;
  doc
    .moveTo(doc.page.margins.left, y)
    .lineTo(doc.page.width - doc.page.margins.right, y)
    .lineWidth(1)
    .strokeColor(COLORS.line)
    .stroke();
  doc.y = y + 8;
}

// label/value rows, two columns. Pre-measures each row's real height so we
// only break to a new page when a row actually won't fit — never mid-row.
function kvTable(doc, rows, labelWidth = 180) {
  const startX = doc.page.margins.left;
  const fullWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const valueWidth = fullWidth - labelWidth;

  rows.forEach(([label, value], i) => {
    const display = value === undefined || value === null || value === '' ? '\u2014' : String(value);

    doc.font('Helvetica').fontSize(10);
    const valueHeight = doc.heightOfString(display, { width: valueWidth });
    doc.font('Helvetica-Bold').fontSize(9.5);
    const labelHeight = doc.heightOfString(label, { width: labelWidth });
    const rowHeight = Math.max(valueHeight, labelHeight, 12);

    ensureSpace(doc, rowHeight + 10);

    const rowY = doc.y;

    doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.muted)
      .text(label, startX, rowY, { width: labelWidth });

    doc.font('Helvetica').fontSize(10).fillColor(COLORS.ink)
      .text(display, startX + labelWidth, rowY, { width: valueWidth });

    doc.y = rowY + rowHeight + 6;
    doc.x = startX;

    if (i < rows.length - 1) {
      doc.moveTo(startX, doc.y - 3).lineTo(startX + fullWidth, doc.y - 3)
        .lineWidth(0.5).strokeColor(COLORS.line).stroke();
    }
  });
  doc.moveDown(0.4);
}

function bulletList(doc, items) {
  const startX = doc.page.margins.left;
  const fullWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  items.forEach((item) => {
    doc.font('Helvetica').fontSize(10);
    const text = '\u2022  ' + item;
    const h = doc.heightOfString(text, { width: fullWidth });
    ensureSpace(doc, h + 6);
    doc.fillColor(COLORS.ink).text(text, startX, doc.y, { width: fullWidth });
    doc.moveDown(0.25);
  });
  doc.moveDown(0.3);
}

function badge(doc, text, color, x, y) {
  const paddingX = 8;
  const height = 18;
  doc.font('Helvetica-Bold').fontSize(9);
  const textWidth = doc.widthOfString(text.toUpperCase());
  const width = textWidth + paddingX * 2;
  doc.roundedRect(x, y, width, height, 3).fillColor(color).fill();
  doc.fillColor('#ffffff').text(text.toUpperCase(), x + paddingX, y + 4, { width: textWidth, lineBreak: false });
  return width;
}

export function generatePdf(doc, caseData) {
  const full = JSON.parse(caseData.analysis_json).analysis;
  const headerForensics = full.header_forensics || {};
  const auth = headerForensics.authentication || {};
  const intel = full.intel || {};
  const geoip = intel.geoip || {};
  const whois = intel.whois || {};
  const hops = headerForensics.relay_chain?.hops || [];

  const pageWidth = doc.page.width;
  const contentWidth = pageWidth - doc.page.margins.left - doc.page.margins.right;

  // ---------- Header band ----------
  const bandHeight = 92;
  doc.rect(0, 0, pageWidth, bandHeight).fill(COLORS.bandBg);

  doc.fillColor(COLORS.bandText).font('Helvetica-Bold').fontSize(16)
    .text('Email Forensic Investigation Report', 50, 24);

  doc.fillColor('#c8d1dc').font('Helvetica').fontSize(9)
    .text(`Case ID: ${caseData.id}`, 50, 48)
    .text(`Generated: ${caseData.created_at}`, 50, 62);

  const vColor = verdictColor(caseData.verdict);
  const badgeText = `${caseData.verdict || 'UNKNOWN'} \u2022 ${caseData.threat_score ?? '\u2014'}/100`;
  doc.font('Helvetica-Bold').fontSize(10);
  const bw = doc.widthOfString(badgeText.toUpperCase()) + 20;
  badge(doc, badgeText, vColor, pageWidth - 50 - bw, 30);

  doc.y = bandHeight + 20;
  doc.x = 50;

  // ---------- Verdict Summary ----------
  sectionTitle(doc, 'Verdict Summary');
  kvTable(doc, [
    ['Threat Score', `${caseData.threat_score} / 100`],
    ['Verdict', caseData.verdict],
    ['Attribution Label', caseData.attribution_label],
    ['Attribution Confidence', `${caseData.attribution_confidence}%`],
    ['Campaign ID', caseData.campaign_id || 'Not correlated with other cases'],
    ['Limited Forensics Mode', caseData.limited_forensics ? 'Yes \u2014 plain text only, header checks skipped' : 'False'],
  ]);

  // ---------- Sender Information ----------
  sectionTitle(doc, 'Sender Information');
  const returnPath = headerForensics.return_path?.return_path_domain || '\u2014';
  kvTable(doc, [
    ['From', caseData.from_address],
    ['From Display Name', '\u2014'],
    ['From Domain', caseData.sender_domain],
    ['Return-Path Domain', returnPath],
    ['Subject', caseData.subject],
    ['Date', '\u2014'],
  ]);

  // ---------- Authentication ----------
  sectionTitle(doc, 'Authentication (SPF / DKIM / DMARC)');
  const authNeutral = !auth.available || (auth.spf === 'neutral' && auth.dkim === 'neutral' && auth.dmarc === 'neutral');
  if (authNeutral) {
    ensureSpace(doc, 20);
    doc.font('Helvetica-Oblique').fontSize(10).fillColor(COLORS.muted)
      .text('Authentication headers unavailable in this input mode.', doc.x, doc.y, { width: contentWidth });
    doc.moveDown(0.6);
  } else {
    kvTable(doc, [
      ['SPF', auth.spf],
      ['DKIM', auth.dkim],
      ['DMARC', auth.dmarc],
      ['Return-Path Mismatch', headerForensics.return_path?.mismatch ? 'True' : 'False'],
    ]);
  }

  // ---------- Network & Geolocation Intelligence ----------
  sectionTitle(doc, 'Network & Geolocation Intelligence');
  kvTable(doc, [
    ['Earliest Public Relay IP', intel.earliest_public_ip || '\u2014'],
    ['Probable Country', geoip.country || '\u2014'],
    ['Probable City', geoip.city || '\u2014'],
    ['ISP / Org', geoip.isp || geoip.org || '\u2014'],
    ['Location Disclaimer', geoip.country ? 'Probable sending infrastructure location \u2014 NOT a confirmed attacker location.' : '\u2014'],
    ['Tor Exit Node', intel.is_tor_exit_node ? 'True' : 'False'],
    ['Known VPN Provider', intel.is_known_vpn ? 'True' : 'False'],
    ['Generic Cloud Hosting', intel.is_cloud_hosting ? 'True' : 'False'],
  ]);

  // ---------- Domain (WHOIS) Intelligence ----------
  sectionTitle(doc, 'Domain (WHOIS) Intelligence');
  kvTable(doc, [
    ['Registrar', whois.registrar || '\u2014'],
    ['Creation Date', whois.creation_date || '\u2014'],
    ['Domain Age (days)', whois.age_days || '\u2014'],
  ]);

  // ---------- Relay Path ----------
  sectionTitle(doc, 'Relay Path (Oldest Hop First)');
  if (hops.length === 0) {
    ensureSpace(doc, 20);
    doc.font('Helvetica-Oblique').fontSize(10).fillColor(COLORS.muted)
      .text('No relay chain available for this input mode.', doc.x, doc.y, { width: contentWidth });
    doc.moveDown(0.6);
  } else {
    hops.forEach((hop) => {
      const line = `Hop ${hop.hop_index}   from ${hop.from_host || 'unknown'} by ${hop.by_host || 'unknown'}  [${hop.ip || hop.network_type || 'unknown'}]`;
      doc.font('Helvetica').fontSize(9.5);
      const h = doc.heightOfString(line, { width: contentWidth });
      ensureSpace(doc, h + 6);
      doc.fillColor(COLORS.ink).text(line, doc.page.margins.left, doc.y, { width: contentWidth });
      doc.moveDown(0.15);
    });
    doc.moveDown(0.3);
  }

  // ---------- Scoring Rationale ----------
  sectionTitle(doc, 'Scoring Rationale');
  bulletList(doc, (full.scoring.reasons && full.scoring.reasons.length)
    ? full.scoring.reasons
    : ['Normal message flow without suspicious indicators']);

  // ---------- Machine Learning Assessment ----------
  sectionTitle(doc, 'Machine Learning Assessment');
  const mlExplanation = full.scoring.ml_explanation || 'No explanation available';
  doc.font('Helvetica').fontSize(10);
  ensureSpace(doc, doc.heightOfString(mlExplanation, { width: contentWidth }) + 6);
  doc.fillColor(COLORS.ink).text(mlExplanation, doc.x, doc.y, { width: contentWidth });
  doc.moveDown(0.5);

  if (full.scoring.ml_top_features && full.scoring.ml_top_features.length) {
    ensureSpace(doc, 20);
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.muted)
      .text('Top phrases driving this classification:', doc.x, doc.y, { width: contentWidth });
    doc.moveDown(0.3);

    const startX = doc.page.margins.left;
    full.scoring.ml_top_features.forEach(([phrase, weight]) => {
      ensureSpace(doc, 18);
      const rowY = doc.y;
      doc.font('Helvetica').fontSize(10).fillColor(COLORS.ink)
        .text(`'${phrase}'`, startX, rowY, { width: contentWidth - 90 });
      doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.muted)
        .text(`weight ${weight}`, startX + contentWidth - 90, rowY, { width: 90, align: 'right' });
      doc.y = Math.max(doc.y, rowY + 14);
      doc.x = startX;
    });
    doc.moveDown(0.3);
  }

  // ---------- Recommended Actions ----------
  sectionTitle(doc, 'Recommended Actions');
  if (full.recommendations.summary) {
    doc.font('Helvetica-Oblique').fontSize(10);
    ensureSpace(doc, doc.heightOfString(full.recommendations.summary, { width: contentWidth }) + 6);
    doc.fillColor(COLORS.muted).text(full.recommendations.summary, doc.x, doc.y, { width: contentWidth });
    doc.moveDown(0.4);
  }
  bulletList(doc, (full.recommendations.actions && full.recommendations.actions.length)
    ? full.recommendations.actions
    : ['No specific actions recommended.']);

  // ---------- Evidence Integrity ----------
  sectionTitle(doc, 'Evidence Integrity');
  kvTable(doc, [
    ['Evidence SHA-256', caseData.evidence_sha256],
  ]);

  // ---------- Attribution Limitations ----------
  sectionTitle(doc, 'Attribution Limitations');
  const limitationsText =
    'The indicators in this report (IP addresses, geolocation, relay hops, and domain intelligence) ' +
    'describe observed sending infrastructure only. An IP address or hosting location is not equivalent ' +
    'to the identity of a person. Email headers, including Received and Authentication-Results headers, ' +
    'can be forged or manipulated by a sufficiently capable actor. All conclusions in this report should ' +
    'be treated as investigative leads requiring further corroboration, not as definitive proof of ' +
    'identity or location.';
  doc.font('Helvetica').fontSize(9.5);
  ensureSpace(doc, doc.heightOfString(limitationsText, { width: contentWidth }) + 6);
  doc.fillColor(COLORS.ink).text(limitationsText, doc.x, doc.y, { width: contentWidth, align: 'justify' });

  // ---------- Footer with page numbers ----------
  // Footer text sits inside the bottom margin, which pdfkit's auto-pagination
  // treats as "overflow" and responds to by silently adding a blank page —
  // so the bottom margin is temporarily zeroed while drawing it.
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(i);
    const savedBottom = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;
    doc.font('Helvetica').fontSize(8).fillColor(COLORS.muted).text(
      `Case ${caseData.id}  \u2022  Page ${i + 1} of ${range.count}`,
      doc.page.margins.left,
      doc.page.height - 35,
      { width: contentWidth, align: 'center', lineBreak: false }
    );
    doc.page.margins.bottom = savedBottom;
  }

  doc.end();
}
