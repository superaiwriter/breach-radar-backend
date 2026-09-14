const express = require('express');
const router = express.Router();

// GET /api/v1/test-cloud-storage/s3-private-bucket -> mock S3 private bucket
router.get('/s3-private-bucket', (req, res) => {
  res.setHeader('Content-Type', 'application/xml');
  res.status(403).send(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>ABCD1234EFGH5678</RequestId>
  <HostId>s3-private-bucket-mock-host-id</HostId>
</Error>`);
});

// GET /api/v1/test-cloud-storage/s3-public-listing-sensitive -> mock S3 public bucket exposing sensitive files
router.get('/s3-public-listing-sensitive', (req, res) => {
  res.setHeader('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-sensitive-bucket</Name>
  <Prefix></Prefix>
  <Marker></Marker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>logo.png</Key>
    <LastModified>2026-08-12T10:00:00.000Z</LastModified>
    <ETag>&quot;a5b6c7d8e9f0&quot;</ETag>
    <Size>51200</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>backup-production.sql</Key>
    <LastModified>2026-08-12T10:05:00.000Z</LastModified>
    <ETag>&quot;b6c7d8e9f0a5&quot;</ETag>
    <Size>471859200</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>credentials.env</Key>
    <LastModified>2026-08-12T10:06:00.000Z</LastModified>
    <ETag>&quot;c7d8e9f0a5b6&quot;</ETag>
    <Size>1228</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>`);
});

// GET /api/v1/test-cloud-storage/s3-public-static-assets -> mock S3 public bucket containing only static assets
router.get('/s3-public-static-assets', (req, res) => {
  res.setHeader('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-static-assets-bucket</Name>
  <Prefix></Prefix>
  <Marker></Marker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>logo.png</Key>
    <LastModified>2026-08-12T10:00:00.000Z</LastModified>
    <ETag>&quot;a5b6c7d8e9f0&quot;</ETag>
    <Size>51200</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>main.js</Key>
    <LastModified>2026-08-12T10:02:00.000Z</LastModified>
    <ETag>&quot;f0a5b6c7d8e9&quot;</ETag>
    <Size>122880</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>theme.css</Key>
    <LastModified>2026-08-12T10:03:00.000Z</LastModified>
    <ETag>&quot;e9f0a5b6c7d8&quot;</ETag>
    <Size>15360</Size>
    <Owner>
      <ID>mock-owner-id</ID>
      <DisplayName>SharmaTech</DisplayName>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>`);
});

module.exports = router;
