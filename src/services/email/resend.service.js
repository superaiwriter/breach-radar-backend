const nodemailer = require('nodemailer');
const logger = require('../../config/logger');

let transporterInstance = null;

function getTransporter() {
  if (!transporterInstance) {
    const host = process.env.SMTP_HOST;
    const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
    const secure = process.env.SMTP_SECURE !== undefined
      ? String(process.env.SMTP_SECURE).toLowerCase() === 'true'
      : port === 465;
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    transporterInstance = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: {
        user,
        pass,
      },
    });
  }
  return transporterInstance;
}

let lastEmailStatus = {
  lastEmailAttempt: null,
  lastEmailError: null,
  lastEmailSuccess: null,
};

function getFrontendInviteBaseUrl() {
  return process.env.FRONTEND_INVITE_BASE_URL || process.env.FRONTEND_URL || 'http://localhost:5173/invite';
}

function formatDate(value) {
  return new Intl.DateTimeFormat('en', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

function getSenderEmail() {
  return process.env.EMAIL_FROM || process.env.SMTP_USER || '';
}

function maskEmailPayload(payload) {
  return {
    from: payload.from,
    to: payload.to,
    subject: payload.subject,
    hasHtml: Boolean(payload.html),
    hasText: Boolean(payload.text),
  };
}

function updateLastEmailStatus({ success, error = null }) {
  lastEmailStatus = {
    lastEmailAttempt: new Date().toISOString(),
    lastEmailError: error,
    lastEmailSuccess: success,
  };
}

function getEmailStatus() {
  const senderEmail = getSenderEmail();
  const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
  return {
    smtpConfigured,
    senderEmail,
    ...lastEmailStatus,
  };
}

// ─── CORE sendEmail FUNCTION ───────────────────────────────────────────────────
async function sendEmail({ to, subject, html, text }) {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = getSenderEmail();
  const emailPayload = { from, to, subject, html, text };

  logger.info(`[email] Sending: ${JSON.stringify(maskEmailPayload(emailPayload))}`);

  if (!host || !user || !pass) {
    const reason = 'SMTP configuration missing in .env';
    updateLastEmailStatus({ success: false, error: reason });
    logger.warn(`[email] ${reason}. Email to ${to} was NOT sent.`);
    const error = new Error('Email provider is not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS in .env');
    error.statusCode = 503;
    error.code = 'SMTP_NOT_CONFIGURED';
    throw error;
  }

  try {
    const transporter = getTransporter();
    const info = await transporter.sendMail(emailPayload);
    logger.info(`[email] SMTP response: ${JSON.stringify({
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      response: info.response,
    })}`);

    updateLastEmailStatus({ success: true });
    logger.info(`[email] Delivered to ${to}. Message ID: ${info.messageId || 'unknown'}`);
    return info;
  } catch (err) {
    updateLastEmailStatus({ success: false, error: err.message });
    logger.error(`[email] Delivery FAILED for ${to}: ${err.message}`);
    throw err;
  }
}

// ─── EMAIL TEMPLATES ───────────────────────────────────────────────────────────

// Template 1: Team Invitation
function buildInvitationEmail({ organizationName, role, token, expiresAt }) {
  const acceptUrl = buildInvitationLink(token);
  const expiry = formatDate(expiresAt);

  return {
    subject: "You've been invited to join PentestRadar",
    html: `
      <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
        <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
            <div style="width:36px;height:36px;background:#16e095;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:18px">B</div>
            <span style="font-size:20px;font-weight:900;color:#ffffff">PentestRadar</span>
          </div>
          <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">You've been invited!</h1>
          <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">You have been invited to collaborate in an organization on PentestRadar.</p>
          <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Organization</p>
            <strong style="display:block;margin-bottom:16px;font-size:18px;color:#ffffff">${organizationName}</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Role Assigned</p>
            <strong style="display:block;margin-bottom:16px;color:#16e095;font-size:16px">${role}</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Invitation Expires</p>
            <strong style="display:block;color:#ffffff">${expiry}</strong>
          </div>
          <a href="${acceptUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
            Accept Invitation →
          </a>
          <p style="margin:24px 0 0;color:#aeb8c7;font-size:13px;line-height:1.6">
            If the button does not work, copy this link:<br>
            <a href="${acceptUrl}" style="color:#16e095">${acceptUrl}</a>
          </p>
          <hr style="margin:24px 0;border:none;border-top:1px solid #20324a">
          <p style="margin:0;color:#6b7a8d;font-size:12px">If you did not expect this invitation, you can safely ignore this email.</p>
        </div>
      </div>
    `,
    text: [
      "You've been invited to join PentestRadar",
      `Organization: ${organizationName}`,
      `Role Assigned: ${role}`,
      `Invitation Expires: ${expiry}`,
      `Accept Invitation: ${acceptUrl}`,
    ].join('\n'),
  };
}

// Template 2: Welcome Email
function buildWelcomeEmail({ name }) {
  const loginUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  return {
    subject: 'Welcome to PentestRadar — Your account is ready!',
    html: `
      <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
        <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
          <div style="text-align:center;margin-bottom:28px">
            <div style="width:64px;height:64px;background:#16e095;border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:32px;margin-bottom:16px">B</div>
            <h1 style="margin:0;font-size:26px;color:#ffffff">Welcome to PentestRadar!</h1>
          </div>
          <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6;font-size:16px">
            Hi <strong style="color:#ffffff">${name}</strong>,<br><br>
            Your account is ready. Start securing your digital assets today.
          </p>
          <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
            <p style="margin:0 0 12px;color:#ffffff;font-weight:700;font-size:15px">What you can do with PentestRadar:</p>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:14px">✅ Scan domains for vulnerabilities</p>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:14px">✅ Monitor SSL certificates & domain expiry</p>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:14px">✅ Get real-time security alerts</p>
            <p style="margin:0;color:#aeb8c7;font-size:14px">✅ Generate professional security reports</p>
          </div>
          <a href="${loginUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
            Go to Dashboard →
          </a>
          <hr style="margin:28px 0;border:none;border-top:1px solid #20324a">
          <p style="margin:0;color:#6b7a8d;font-size:12px;text-align:center">
            PentestRadar — Enterprise Security Platform
          </p>
        </div>
      </div>
    `,
    text: `Welcome to PentestRadar, ${name}!\n\nYour account is ready.\n\nLog in here: ${loginUrl}`,
  };
}

// Template 3: Password Reset (already in auth.service.js but reusable here too)
function buildPasswordResetEmail({ email, resetUrl }) {
  return {
    subject: 'PentestRadar — Reset Your Password',
    html: `
      <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
        <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
            <div style="width:36px;height:36px;background:#16e095;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:18px">B</div>
            <span style="font-size:20px;font-weight:900;color:#ffffff">PentestRadar</span>
          </div>
          <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">Reset Your Password</h1>
          <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">
            We received a request to reset the password for your account.
          </p>
          <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px">Account Email</p>
            <strong style="display:block;margin-bottom:16px;color:#ffffff">${email}</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px">Link Expires In</p>
            <strong style="display:block;color:#16e095">1 Hour</strong>
          </div>
          <a href="${resetUrl}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
            Reset Password →
          </a>
          <p style="margin:24px 0 0;color:#aeb8c7;font-size:13px;line-height:1.6">
            If you did not request this, ignore this email — your password will not change.<br><br>
            If the button does not work:<br>
            <a href="${resetUrl}" style="color:#16e095">${resetUrl}</a>
          </p>
          <hr style="margin:24px 0;border:none;border-top:1px solid #20324a">
          <p style="margin:0;color:#6b7a8d;font-size:12px">This link expires in 1 hour for security reasons.</p>
        </div>
      </div>
    `,
    text: `Reset Your Password\n\nClick to reset: ${resetUrl}\n\nExpires in 1 hour.\n\nIf you did not request this, ignore this email.`,
  };
}

// Template 4: Invoice Email
function buildInvoiceEmail({ invoiceNumber, planName, amount, date, downloadLink }) {
  const formattedAmount = new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 0
  }).format(amount);

  return {
    subject: `PentestRadar Invoice — ${invoiceNumber}`,
    html: `
      <div style="margin:0;background:#07111f;padding:32px;font-family:Inter,Segoe UI,Arial,sans-serif;color:#f8fafc">
        <div style="max-width:620px;margin:0 auto;background:#0b1728;border:1px solid #20324a;border-radius:12px;padding:28px">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px">
            <div style="width:36px;height:36px;background:#16e095;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-weight:900;color:#04120d;font-size:18px">B</div>
            <span style="font-size:20px;font-weight:900;color:#ffffff">PentestRadar</span>
          </div>
          <h1 style="margin:0 0 12px;font-size:24px;color:#ffffff">Payment Successful!</h1>
          <p style="margin:0 0 22px;color:#aeb8c7;line-height:1.6">Thank you for your payment. Here are your subscription details.</p>
          <div style="background:#091421;border:1px solid #20324a;border-radius:10px;padding:18px;margin-bottom:22px">
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Invoice Number</p>
            <strong style="display:block;margin-bottom:16px;font-size:16px;color:#ffffff">${invoiceNumber}</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Plan</p>
            <strong style="display:block;margin-bottom:16px;color:#16e095;font-size:16px">${planName} Plan</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Amount Paid</p>
            <strong style="display:block;margin-bottom:16px;font-size:20px;color:#ffffff">${formattedAmount}</strong>
            <p style="margin:0 0 8px;color:#aeb8c7;font-size:13px;text-transform:uppercase;letter-spacing:0.5px">Date</p>
            <strong style="display:block;color:#ffffff">${new Date(date).toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' })}</strong>
          </div>
          <a href="${downloadLink}" style="display:inline-block;background:#16e095;color:#04120d;text-decoration:none;font-weight:800;padding:14px 28px;border-radius:8px;font-size:16px">
            Download PDF Invoice →
          </a>
          <hr style="margin:28px 0;border:none;border-top:1px solid #20324a">
          <p style="margin:0;color:#6b7a8d;font-size:12px;text-align:center">
            Thank you for choosing PentestRadar!
          </p>
        </div>
      </div>
    `,
    text: `Payment Successful!\nInvoice: ${invoiceNumber}\nPlan: ${planName}\nAmount: ${formattedAmount}\nDate: ${new Date(date).toLocaleDateString()}\nDownload: ${downloadLink}`,
  };
}

function buildInvitationLink(token) {
  return `${getFrontendInviteBaseUrl()}/${token}`;
}

async function sendInvitationEmail({ to, organizationName, role, token, expiresAt }) {
  const template = buildInvitationEmail({ organizationName, role, token, expiresAt });
  return sendEmail({ to, ...template });
}

async function sendWelcomeEmail({ to, name }) {
  const template = buildWelcomeEmail({ name });
  return sendEmail({ to, ...template });
}

async function sendInvoiceEmail({ to, invoiceNumber, planName, amount, date, downloadLink }) {
  const template = buildInvoiceEmail({ invoiceNumber, planName, amount, date, downloadLink });
  return sendEmail({ to, ...template });
}

async function verifySenderDomainStatus() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const senderEmail = getSenderEmail();

  const configured = Boolean(host && user && pass);

  if (!configured) {
    return {
      configured: false,
      senderEmail,
      verified: false,
      reason: 'SMTP configuration missing in .env',
    };
  }

  try {
    const transporter = getTransporter();
    await transporter.verify();
    return {
      configured: true,
      senderEmail,
      verified: true,
      reason: 'SMTP connection verified successfully.',
    };
  } catch (err) {
    return {
      configured: true,
      senderEmail,
      verified: false,
      reason: err.message || 'SMTP connection verification failed.',
    };
  }
}

module.exports = {
  sendEmail,
  sendInvitationEmail,
  sendWelcomeEmail,
  sendInvoiceEmail,
  buildInvitationEmail,
  buildWelcomeEmail,
  buildPasswordResetEmail,
  buildInvoiceEmail,
  buildInvitationLink,
  getEmailStatus,
  verifySenderDomainStatus,
};
