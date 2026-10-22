import { constants, privateEncrypt } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import forge from 'node-forge';
import { validateSignature } from '../js/logic/validate-signature-pdf';

// All keys and documents are generated locally for tests; no private user data.
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'binary'));
const keyPair = () => forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
type Keys = ReturnType<typeof keyPair>;
let rootKeys: Keys;
let leafKeys: Keys;

function certificate(
  keys: Keys,
  name: string,
  issuer?: { cert: forge.pki.Certificate; keys: Keys },
  ca = false
) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = name === 'Root' ? '01' : '02';
  cert.setSubject([{ name: 'commonName', value: name }]);
  cert.setIssuer(issuer?.cert.subject.attributes ?? cert.subject.attributes);
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  cert.setExtensions([
    { name: 'basicConstraints', cA: ca },
    { name: 'keyUsage', keyCertSign: ca, digitalSignature: true },
  ]);
  cert.sign(
    issuer?.keys.privateKey ?? keys.privateKey,
    forge.md.sha256.create()
  );
  return cert;
}

function malformedSignature(digest: string, keys: Keys): string {
  const { create, Class, Type, oidToDer, toDer } = forge.asn1;
  const digestInfo = create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    create(Class.UNIVERSAL, Type.SEQUENCE, true, [
      create(
        Class.UNIVERSAL,
        Type.OID,
        false,
        oidToDer(forge.pki.oids.sha256).getBytes()
      ),
      create(Class.UNIVERSAL, Type.NULL, false, ''),
      create(Class.UNIVERSAL, Type.OCTETSTRING, false, 'extra nested element'),
    ]),
    create(Class.UNIVERSAL, Type.OCTETSTRING, false, digest),
  ]);
  return privateEncrypt(
    {
      key: forge.pki.privateKeyToPem(keys.privateKey),
      padding: constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(toDer(digestInfo).getBytes(), 'binary')
  ).toString('binary');
}

function document(
  cert: forge.pki.Certificate,
  extras: forge.pki.Certificate[] = [],
  malformed = false,
  unsignedPrefix = 0
) {
  const content = '%PDF-1.4\nsynthetic signature regression\n%%EOF';
  const pdfBytes = bytes(content);
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(content.slice(unsignedPrefix));
  p7.addCertificate(cert);
  extras.forEach((extra) => p7.addCertificate(extra));
  p7.addSigner({
    key: leafKeys.privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
  });
  p7.sign({ detached: true });
  const cms = p7.toAsn1();
  if (malformed) {
    const md = forge.md.sha256.create();
    md.update(content);
    const contentWrapper = (cms.value as forge.asn1.Asn1[])[1];
    const signedData = (contentWrapper.value as forge.asn1.Asn1[])[0];
    const signerInfos = (signedData.value as forge.asn1.Asn1[]).at(-1)!;
    const signerInfo = (signerInfos.value as forge.asn1.Asn1[])[0];
    const signatureNode = (signerInfo.value as forge.asn1.Asn1[]).find(
      (node) => node.type === forge.asn1.Type.OCTETSTRING
    )!;
    signatureNode.value = malformedSignature(md.digest().bytes(), leafKeys);
  }
  return {
    pdfBytes,
    signature: {
      index: 0,
      contents: bytes(forge.asn1.toDer(cms).getBytes()),
      byteRange: [
        unsignedPrefix,
        pdfBytes.length - unsignedPrefix,
        pdfBytes.length,
        0,
      ],
    },
  };
}

describe('signature verification security', () => {
  beforeAll(() => {
    rootKeys = keyPair();
    leafKeys = keyPair();
  });

  it('accepts a valid document and its directly trusted issuer', async () => {
    const root = certificate(rootKeys, 'Root', undefined, true);
    const leaf = certificate(leafKeys, 'Leaf', { cert: root, keys: rootKeys });
    const doc = document(leaf, [root]);
    const result = await validateSignature(doc.signature, doc.pdfBytes, root);
    expect(result.cryptoVerified).toBe(true);
    expect(result.isTrusted).toBe(true);
  });

  it('rejects extra nested DigestAlgorithm elements in a document signature', async () => {
    const leaf = certificate(leafKeys, 'Leaf');
    const doc = document(leaf, [], true);
    const result = await validateSignature(doc.signature, doc.pdfBytes);
    expect(result.cryptoVerified).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it('does not label a signed suffix as a fully verified PDF', async () => {
    const leaf = certificate(leafKeys, 'Leaf');
    const doc = document(leaf, [], false, 12);
    const result = await validateSignature(doc.signature, doc.pdfBytes);
    expect(result.cryptoVerified).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it('accepts a connected chain through a signing CA', async () => {
    const root = certificate(rootKeys, 'Root', undefined, true);
    const intermediateKeys = keyPair();
    const intermediate = certificate(
      intermediateKeys,
      'Intermediate',
      { cert: root, keys: rootKeys },
      true
    );
    const leaf = certificate(leafKeys, 'Leaf', {
      cert: intermediate,
      keys: intermediateKeys,
    });
    const doc = document(leaf, [intermediate, root]);
    const result = await validateSignature(doc.signature, doc.pdfBytes, root);
    expect(result.isTrusted).toBe(true);
  });

  it('does not use a non-CA certificate as an intermediate', async () => {
    const root = certificate(rootKeys, 'Root', undefined, true);
    const intermediateKeys = keyPair();
    const intermediate = certificate(intermediateKeys, 'Intermediate', {
      cert: root,
      keys: rootKeys,
    });
    const leaf = certificate(leafKeys, 'Leaf', {
      cert: intermediate,
      keys: intermediateKeys,
    });
    const doc = document(leaf, [intermediate, root]);
    const result = await validateSignature(doc.signature, doc.pdfBytes, root);
    expect(result.isTrusted).toBe(false);
  });

  it('rejects the same malformed encoding in the signer certificate', async () => {
    const root = certificate(rootKeys, 'Root', undefined, true);
    const leaf = certificate(leafKeys, 'Leaf', { cert: root, keys: rootKeys });
    const value = forge.pki.certificateToAsn1(leaf).value as forge.asn1.Asn1[];
    const md = forge.md.sha256.create();
    md.update(forge.asn1.toDer(value[0]).getBytes());
    leaf.signature = malformedSignature(md.digest().bytes(), rootKeys);
    const doc = document(leaf);
    const result = await validateSignature(doc.signature, doc.pdfBytes, root);
    expect(result.cryptoVerified).toBe(true);
    expect(result.isTrusted).toBe(false);
  });

  it('does not trust an unrelated signer because the CMS includes the trusted certificate', async () => {
    const root = certificate(rootKeys, 'Root', undefined, true);
    const leaf = certificate(leafKeys, 'Unrelated');
    const doc = document(leaf, [root]);
    const result = await validateSignature(doc.signature, doc.pdfBytes, root);
    expect(result.cryptoVerified).toBe(true);
    expect(result.isTrusted).toBe(false);
  });

  it('fails closed when the browser cryptography API is unavailable', async () => {
    const leaf = certificate(leafKeys, 'Leaf');
    const doc = document(leaf);
    vi.stubGlobal('crypto', {});
    try {
      const result = await validateSignature(doc.signature, doc.pdfBytes);
      expect(result.cryptoVerified).toBe(false);
      expect(result.cryptoVerificationStatus).toBe('unsupported');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
