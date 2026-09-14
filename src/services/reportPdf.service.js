const PDFDocument = require('pdfkit');

const WATERMARK_TEXT = 'pentestradar.com';

const DEFAULT_SECTIONS = [
  'Vulnerability Details',
  'Risk Analysis',
  'Remediation Steps',
  'Scan Summary',
  'OWASP Top 10',
  'Executive Summary'
];

function addWatermark(doc, text = WATERMARK_TEXT) {
  const pageWidth = doc.page.width;
  const pageHeight = doc.page.height;
  const centerX = pageWidth / 2;
  const centerY = pageHeight / 2;

  doc.save();
  doc.opacity(0.08);
  doc.fillColor('#00d68f');
  doc.font('Helvetica-Bold').fontSize(52);
  doc.rotate(-35, { origin: [centerX, centerY] });
  doc.text(text, centerX - 220, centerY - 24, {
    width: 440,
    align: 'center'
  });
  doc.restore();
}

class ReportPdfService {
  generateReportPdf(report) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ size: 'A4', margin: 50 });
        const chunks = [];

        doc.on('data', (chunk) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', (err) => reject(err));

        addWatermark(doc);

        const vulns = report.vulns || [0, 0, 0, 0]; const [critical, high, medium, low] = vulns;
        const totalFindings = vulns.reduce((sum, value) => sum + (Number(value) || 0), 0);
        const generatedLines = String(report.generated || '').split('\n');
        const generatedDate = generatedLines[0] || '-';
        const generatedTime = generatedLines[1] || '-';
        const sections = report.sections?.length ? report.sections : DEFAULT_SECTIONS;

        doc.fillColor('#00d68f')
          .fontSize(24)
          .font('Helvetica-Bold')
          .text('PENTESTRADAR', 50, 50);

        doc.fillColor('#64748b')
          .fontSize(10)
          .font('Helvetica')
          .text('Security Assessment Report', 50, 78);

        doc.fillColor('#0f172a')
          .fontSize(18)
          .font('Helvetica-Bold')
          .text('SECURITY REPORT', 330, 50, { align: 'right', width: 215 });

        doc.moveTo(50, 105)
          .lineTo(545, 105)
          .strokeColor('#cbd5e1')
          .lineWidth(1)
          .stroke();

        doc.fillColor('#0f172a')
          .fontSize(16)
          .font('Helvetica-Bold')
          .text(report.title || 'Security Scan Report', 50, 125);

        doc.fillColor('#475569')
          .fontSize(11)
          .font('Helvetica')
          .text(`Report ID: ${report.id || '-'}`, 50, 150)
          .text(`Domain: ${report.domain || '-'}`, 50, 167)
          .text(`Scan Type: ${report.scanType || '-'}`, 50, 184)
          .text(`Status: ${report.status || '-'}`, 50, 201)
          .text(`Owner: ${report.owner || 'Security Team'}`, 50, 218)
          .text(`Generated: ${generatedDate} ${generatedTime}`, 50, 235);

        doc.fillColor('#0f172a')
          .fontSize(13)
          .font('Helvetica-Bold')
          .text('Security Score', 330, 150);

        const score = report.score ?? null;
        doc.fillColor(score === null ? '#64748b' : score >= 70 ? '#00d68f' : score >= 55 ? '#f59e0b' : '#ef4444')
          .fontSize(34)
          .font('Helvetica-Bold')
          .text(score === null ? '—' : String(score), 330, 172);

        doc.fillColor('#64748b')
          .fontSize(11)
          .font('Helvetica')
          .text('/100', score === null ? 360 : 380, 188);

        doc.moveTo(50, 265)
          .lineTo(545, 265)
          .strokeColor('#e2e8f0')
          .lineWidth(1)
          .stroke();

        doc.fillColor('#0f172a')
          .fontSize(13)
          .font('Helvetica-Bold')
          .text('Findings Summary', 50, 285);

        const summaryRows = [
          ['Severity', 'Count'],
          ['Critical', String(critical).padStart(2, '0')],
          ['High', String(high).padStart(2, '0')],
          ['Medium', String(medium).padStart(2, '0')],
          ['Low', String(low).padStart(2, '0')],
          ['Total', String(totalFindings)]
        ];

        let tableY = 310;
        summaryRows.forEach((row, index) => {
          const isHeader = index === 0;
          if (isHeader) {
            doc.rect(50, tableY - 4, 495, 22).fill('#f1f5f9');
          }

          doc.fillColor(isHeader ? '#0f172a' : '#334155')
            .font(isHeader ? 'Helvetica-Bold' : 'Helvetica')
            .fontSize(isHeader ? 11 : 10)
            .text(row[0], 60, tableY, { width: 220 })
            .text(row[1], 420, tableY, { width: 100, align: 'right' });

          tableY += 24;
        });

        doc.fillColor('#0f172a')
          .fontSize(13)
          .font('Helvetica-Bold')
          .text('Included Sections', 50, tableY + 18);

        let sectionY = tableY + 42;
        sections.forEach((section) => {
          doc.fillColor('#00d68f')
            .fontSize(10)
            .font('Helvetica-Bold')
            .text('•', 50, sectionY);

          doc.fillColor('#334155')
            .font('Helvetica')
            .text(section, 65, sectionY);

          sectionY += 18;
        });

        doc.fillColor('#0f172a')
          .fontSize(13)
          .font('Helvetica-Bold')
          .text('Executive Summary', 50, sectionY + 16);

        doc.fillColor('#475569')
          .fontSize(10)
          .font('Helvetica')
          .text(
            `This report summarizes the latest ${report.scanType || 'security'} assessment for ${report.domain || 'the selected domain'}. ` +
            `The current security score is ${score === null ? 'pending' : `${score}/100`} with ${totalFindings} total open findings across all severity levels. ` +
            'Review the vulnerability details, risk analysis, and remediation steps included in this report to prioritize fixes.',
            50,
            sectionY + 38,
            { width: 495, align: 'left', lineGap: 4 }
          );

        const footerY = 760;
        doc.moveTo(50, footerY)
          .lineTo(545, footerY)
          .strokeColor('#e2e8f0')
          .lineWidth(1)
          .stroke();

        doc.fillColor('#94a3b8')
          .fontSize(9)
          .font('Helvetica')
          .text(`Generated by PentestRadar (${WATERMARK_TEXT}) • Confidential Security Report`, 50, footerY + 12, {
            width: 495,
            align: 'center'
          });
        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }
}

module.exports = new ReportPdfService();
