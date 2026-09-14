const net = require('net');

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain'
]);

const BLOCKED_TLDS = new Set([
  'local',
  'localhost',
  'internal',
  'test',
  'invalid',
  'example'
]);

const normalizeDomainName = (domain) => {
  if (typeof domain !== 'string') {
    return '';
  }

  return domain.trim().toLowerCase().replace(/\.$/, '');
};

const validateDomainFormat = (domain) => {
  const normalizedDomain = normalizeDomainName(domain);
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  return domainRegex.test(normalizedDomain);
};

const validatePublicDomainTarget = (domain) => {
  const normalizedDomain = normalizeDomainName(domain);

  if (process.env.NODE_ENV === 'development') {
    const isLocalhost = normalizedDomain === 'localhost' || normalizedDomain.startsWith('localhost:');
    const isLocalIp = normalizedDomain === '127.0.0.1' || normalizedDomain.startsWith('127.0.0.1:');
    if (isLocalhost || isLocalIp) {
      return {
        valid: true,
        domain: normalizedDomain
      };
    }
  }

  if (!validateDomainFormat(normalizedDomain)) {
    return {
      valid: false,
      message: 'Invalid domain name format.'
    };
  }

  if (net.isIP(normalizedDomain)) {
    return {
      valid: false,
      message: 'IP addresses cannot be added as scan targets.'
    };
  }

  if (BLOCKED_HOSTNAMES.has(normalizedDomain)) {
    return {
      valid: false,
      message: 'Localhost/internal targets cannot be scanned.'
    };
  }

  const labels = normalizedDomain.split('.');
  const tld = labels[labels.length - 1];

  if (labels.includes('localhost') || BLOCKED_TLDS.has(tld)) {
    return {
      valid: false,
      message: 'Reserved or internal domains cannot be scanned.'
    };
  }

  return {
    valid: true,
    domain: normalizedDomain
  };
};

const validateEmailFormat = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

module.exports = {
  normalizeDomainName,
  validateDomainFormat,
  validatePublicDomainTarget,
  validateEmailFormat
};
