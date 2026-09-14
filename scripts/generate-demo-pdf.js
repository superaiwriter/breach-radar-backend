const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

const outputPath = path.join(__dirname, '..', '..', 'frontent', 'public', 'sample-report.pdf');

function addWatermark(doc, text = 'pentestradar.com') {
  const pageWidth = doc.page.width;
  const pageHeight = doc.page.height;
  const centerX = pageWidth / 2;
  const centerY = pageHeight / 2;

  doc.save();
  doc.opacity(0.06);
  doc.fillColor('#00d68f');
  doc.font('Helvetica-Bold').fontSize(52);
  doc.rotate(-35, { origin: [centerX, centerY] });
  doc.text(text, centerX - 220, centerY - 24, {
    width: 440,
    align: 'center'
  });
  doc.restore();
}

function drawHeader(doc, pageNum, totalPages) {
  addWatermark(doc);

  doc.fillColor('#00d68f')
    .fontSize(24)
    .font('Helvetica-Bold')
    .text('PENTESTRADAR', 50, 40);

  doc.fillColor('#64748b')
    .fontSize(9)
    .font('Helvetica')
    .text('Security Assessment Report', 50, 68);

  doc.fillColor('#0f172a')
    .fontSize(16)
    .font('Helvetica-Bold')
    .text('SECURITY REPORT', 330, 40, { align: 'right', width: 215 });

  doc.moveTo(50, 90)
    .lineTo(545, 90)
    .strokeColor('#cbd5e1')
    .lineWidth(1)
    .stroke();

  // Footer page number
  doc.fillColor('#94a3b8')
    .fontSize(9)
    .font('Helvetica')
    .text(`Page ${pageNum} of ${totalPages}`, 50, 800, { align: 'center', width: 495 });
}

function generatePDF() {
  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  const writeStream = fs.createWriteStream(outputPath);
  doc.pipe(writeStream);

  const totalPages = 3;

  // --- PAGE 1 ---
  drawHeader(doc, 1, totalPages);

  doc.fillColor('#0f172a')
    .fontSize(16)
    .font('Helvetica-Bold')
    .text('easypdfeditor.online', 50, 110)
    .fontSize(12)
    .font('Helvetica')
    .text('Domain', 50, 130);

  // Metadata block
  doc.rect(50, 160, 495, 50).fillColor('#f8fafc').fill();
  
  doc.fillColor('#64748b').fontSize(8).font('Helvetica-Bold')
    .text('Domain', 60, 168)
    .text('Generated Date', 160, 168)
    .text('Generated Time', 280, 168)
    .text('Security Score', 410, 168);

  doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold')
    .text('easypdfeditor.online', 60, 182)
    .text('11 August 2026', 160, 182)
    .text('12:30:45 pm', 280, 182);

  doc.fillColor('#ef4444').fontSize(12).font('Helvetica-Bold')
    .text('30/100', 410, 182);

  // Summary header
  doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('SUMMARY', 50, 235);
  doc.moveTo(50, 255).lineTo(545, 255).strokeColor('#00d68f').lineWidth(2).stroke();

  // Metrics Grid
  const startY = 270;
  const colW = 115;
  const boxH = 45;
  const gap = 11;

  const summaryMetrics = [
    { label: 'Total Vulnerabilities', val: '38' },
    { label: 'Critical', val: '0' },
    { label: 'High', val: '6' },
    { label: 'Medium', val: '12' },
    { label: 'Low', val: '20' },
    { label: 'Open', val: '38' },
    { label: 'Resolved', val: '0' },
  ];

  summaryMetrics.forEach((m, idx) => {
    const row = Math.floor(idx / 4);
    const col = idx % 4;
    const x = 50 + col * (colW + gap);
    const y = startY + row * (boxH + gap);

    doc.rect(x, y, colW, boxH).fillColor('#f8fafc').fill();
    doc.fillColor('#64748b').fontSize(7).font('Helvetica-Bold').text(m.label, x + 8, y + 8);
    doc.fillColor('#0f172a').fontSize(16).font('Helvetica-Bold').text(m.val, x + 8, y + 18);
  });

  // Section: Vulnerabilities
  doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('Vulnerability Details', 50, 400);
  doc.moveTo(50, 420).lineTo(545, 420).strokeColor('#00d68f').lineWidth(2).stroke();

  // VULNERABILITY #1 Box
  doc.rect(50, 435, 495, 20).fillColor('#f1f5f9').fill();
  doc.fillColor('#0f172a').fontSize(10).font('Helvetica-Bold').text('VULNERABILITY #1', 60, 440);

  // Details fields
  const fields = [
    { label: 'Name:', val: 'Session Cookie Missing HttpOnly Flag' },
    { label: 'Severity:', val: 'High' },
    { label: 'Status:', val: 'Open' },
    { label: 'Detected Date:', val: '10 Aug 2026, 12:15 pm' },
    { label: 'Affected URL:', val: '/' },
    { label: 'CWE:', val: 'CWE-1004' },
    { label: 'CVE:', val: '-' }
  ];

  let currentY = 465;
  fields.forEach(f => {
    doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(f.label, 60, currentY);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(f.val, 160, currentY);
    currentY += 14;
  });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Description', 60, currentY + 4);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('The session cookie "XSRF-TOKEN" is missing the HttpOnly attribute.', 60, currentY + 16);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Impact', 60, currentY + 36);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Cross-Site Scripting (XSS) attacks can be used by an attacker to steal the session cookie.', 60, currentY + 48);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Recommended Fix', 60, currentY + 68);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Set the HttpOnly attribute on session cookies.', 60, currentY + 80);


  // --- PAGE 2 ---
  doc.addPage();
  drawHeader(doc, 2, totalPages);

  // VULNERABILITY #2 Box
  doc.rect(50, 110, 495, 20).fillColor('#f1f5f9').fill();
  doc.fillColor('#0f172a').fontSize(10).font('Helvetica-Bold').text('VULNERABILITY #2', 60, 115);

  const fields2 = [
    { label: 'Name:', val: 'No Password Strength Meter Detected' },
    { label: 'Severity:', val: 'Low' },
    { label: 'Status:', val: 'Open' },
    { label: 'Detected Date:', val: '10 Aug 2026, 12:15 pm' },
    { label: 'Affected URL:', val: '/register' },
    { label: 'CWE:', val: '-' },
    { label: 'CVE:', val: '-' }
  ];

  let currentY2 = 140;
  fields2.forEach(f => {
    doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(f.label, 60, currentY2);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(f.val, 160, currentY2);
    currentY2 += 14;
  });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Description', 60, currentY2 + 4);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('No visual password strength indicator was detected on the registration form at /register.', 60, currentY2 + 16);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Impact', 60, currentY2 + 36);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Without real-time feedback, users are less likely to choose stronger passwords voluntarily.', 60, currentY2 + 48);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Recommended Fix', 60, currentY2 + 68);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Add a password strength meter (e.g. zxcvbn) to guide users toward stronger passwords at registration.', 60, currentY2 + 80);


  // VULNERABILITY #3 Box
  const v3StartY = 370;
  doc.rect(50, v3StartY, 495, 20).fillColor('#f1f5f9').fill();
  doc.fillColor('#0f172a').fontSize(10).font('Helvetica-Bold').text('VULNERABILITY #3', 60, v3StartY + 5);

  const fields3 = [
    { label: 'Name:', val: 'Weak Password Policy' },
    { label: 'Severity:', val: 'High' },
    { label: 'Status:', val: 'Open' },
    { label: 'Detected Date:', val: '10 Aug 2026, 12:15 pm' },
    { label: 'Affected URL:', val: '/register' },
    { label: 'CWE:', val: 'CWE-521' },
    { label: 'CVE:', val: '-' }
  ];

  let currentY3 = v3StartY + 30;
  fields3.forEach(f => {
    doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(f.label, 60, currentY3);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(f.val, 160, currentY3);
    currentY3 += 14;
  });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Description', 60, currentY3 + 4);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('The registration form at /register appears to enforce few or no password complexity requirements (missing: minimum length, uppercase letter, lowercase letter, number, special character).', 60, currentY3 + 16, { width: 470 });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Impact', 60, currentY3 + 56);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('A weak password policy makes user accounts significantly easier to compromise via brute-force, dictionary, or credential-stuffing attacks.', 60, currentY3 + 68, { width: 470 });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Recommended Fix', 60, currentY3 + 108);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Adopt a password policy requiring at least 8 characters with a mix of uppercase, lowercase, numbers, and special characters - or adopt NIST 800-63B guidance (long passphrases + breached-password screening).', 60, currentY3 + 120, { width: 470 });


  // --- PAGE 3 ---
  doc.addPage();
  drawHeader(doc, 3, totalPages);

  // VULNERABILITY #4 Box
  doc.rect(50, 110, 495, 20).fillColor('#f1f5f9').fill();
  doc.fillColor('#0f172a').fontSize(10).font('Helvetica-Bold').text('VULNERABILITY #4', 60, 115);

  const fields4 = [
    { label: 'Name:', val: 'Special Character Not Required' },
    { label: 'Severity:', val: 'Low' },
    { label: 'Status:', val: 'Open' },
    { label: 'Detected Date:', val: '10 Aug 2026, 12:15 pm' },
    { label: 'Affected URL:', val: '/register' },
    { label: 'CWE:', val: 'CWE-521' },
    { label: 'CVE:', val: '-' }
  ];

  let currentY4 = 140;
  fields4.forEach(f => {
    doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(f.label, 60, currentY4);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(f.val, 160, currentY4);
    currentY4 += 14;
  });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Description', 60, currentY4 + 4);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('The registration form at /register does not appear to require a special character in the password.', 60, currentY4 + 16);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Impact', 60, currentY4 + 36);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Passwords without a required special character have a smaller character space, reducing brute-force resistance.', 60, currentY4 + 48);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Recommended Fix', 60, currentY4 + 68);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Require at least one special character in the password policy.', 60, currentY4 + 80);


  // VULNERABILITY #5 Box
  const v5StartY = 370;
  doc.rect(50, v5StartY, 495, 20).fillColor('#f1f5f9').fill();
  doc.fillColor('#0f172a').fontSize(10).font('Helvetica-Bold').text('VULNERABILITY #5', 60, v5StartY + 5);

  const fields5 = [
    { label: 'Name:', val: 'Numeric Character Not Required' },
    { label: 'Severity:', val: 'Low' },
    { label: 'Status:', val: 'Open' },
    { label: 'Detected Date:', val: '10 Aug 2026, 12:15 pm' },
    { label: 'Affected URL:', val: '/register' },
    { label: 'CWE:', val: 'CWE-521' },
    { label: 'CVE:', val: '-' }
  ];

  let currentY5 = v5StartY + 30;
  fields5.forEach(f => {
    doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text(f.label, 60, currentY5);
    doc.fillColor('#334155').fontSize(9).font('Helvetica').text(f.val, 160, currentY5);
    currentY5 += 14;
  });

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Description', 60, currentY5 + 4);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('The registration form at /register does not appear to require a number in the password.', 60, currentY5 + 16);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Impact', 60, currentY5 + 36);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Passwords without a required number have a smaller character space, reducing brute-force resistance.', 60, currentY5 + 48);

  doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold').text('Recommended Fix', 60, currentY5 + 68);
  doc.fillColor('#334155').fontSize(9).font('Helvetica').text('Require at least one number in the password policy.', 60, currentY5 + 80);

  doc.fillColor('#94a3b8')
    .fontSize(8)
    .font('Helvetica-Oblique')
    .text('Generated by PentestRadar (pentestradar.com) - Confidential Security Report', 50, 770, { align: 'center', width: 495 });

  doc.end();

  writeStream.on('finish', () => {
    console.log('PDF Generated Successfully at:', outputPath);
  });
}

generatePDF();
